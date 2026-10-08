//! The clock model's normal equations as a block-banded matrix with an arrow border (crate docs,
//! § The least-squares problem): one block per time slice (every clock's offset at one knot, in
//! key order), slices coupled to at most `BAND` neighbours on either side, and the aircraft's baro
//! biases as a dense border eliminated last. Factored by block Cholesky in one fixed order
//! (slices in time order, then the border), solved, and inverted selectively: only the blocks
//! inside the factor's pattern (the band and the border) are computed, by Takahashi's recurrence,
//! never the full inverse. Every loop runs in one fixed order, so the same matrix gives the same
//! bits.

/// How many slices apart two coupled slices may be: the second-difference prior couples a knot
/// with the knots two either side, and an event couples the knots around its receptions, which
/// the fit keeps within one interval of each other.
pub const BAND: usize = 2;

/// A dense block, row major.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<f64>,
}

impl Block {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0.0; rows * cols],
        }
    }

    pub fn get(&self, row: usize, col: usize) -> f64 {
        self.data[row * self.cols + col]
    }

    pub fn add(&mut self, row: usize, col: usize, value: f64) {
        self.data[row * self.cols + col] += value;
    }

    fn set(&mut self, row: usize, col: usize, value: f64) {
        self.data[row * self.cols + col] = value;
    }

    fn transpose(&self) -> Self {
        let mut out = Self::zeros(self.cols, self.rows);
        for r in 0..self.rows {
            for c in 0..self.cols {
                out.set(c, r, self.get(r, c));
            }
        }
        out
    }

    /// `self - a bᵀ`, accumulated into self.
    fn sub_mul_t(&mut self, a: &Self, b: &Self) {
        let k = a.cols;
        for r in 0..self.rows {
            let left = &a.data[r * k..(r + 1) * k];
            let row = &mut self.data[r * self.cols..(r + 1) * self.cols];
            for (c, out) in row.iter_mut().enumerate() {
                *out -= dot(left, &b.data[c * k..(c + 1) * k]);
            }
        }
    }

    /// `self - a aᵀ` on and below the diagonal only: what `cholesky` reads.
    fn sub_mul_t_lower(&mut self, a: &Self) {
        let k = a.cols;
        for r in 0..self.rows {
            let left = &a.data[r * k..(r + 1) * k];
            let row = &mut self.data[r * self.cols..r * self.cols + r + 1];
            for (c, out) in row.iter_mut().enumerate() {
                *out -= dot(left, &a.data[c * k..(c + 1) * k]);
            }
        }
    }

    /// `self + a b`, accumulated into self.
    fn add_mul(&mut self, a: &Self, b: &Self) {
        let cols = self.cols;
        for r in 0..self.rows {
            let row = &mut self.data[r * cols..(r + 1) * cols];
            for k in 0..a.cols {
                let factor = a.data[r * a.cols + k];
                if factor == 0.0 {
                    continue;
                }
                let other = &b.data[k * b.cols..(k + 1) * b.cols];
                for (out, value) in row.iter_mut().zip(other) {
                    *out += factor * value;
                }
            }
        }
    }

    /// The lower Cholesky factor, or `None` when not positive definite.
    fn cholesky(&self) -> Option<Self> {
        let n = self.rows;
        let mut l = Self::zeros(n, n);
        for j in 0..n {
            let (done, rest) = l.data.split_at_mut(j * n);
            let _ = done;
            let row_j = &rest[..j];
            let diagonal = self.get(j, j) - dot(row_j, row_j);
            if diagonal.is_nan() || diagonal <= 0.0 {
                return None;
            }
            let root = diagonal.sqrt();
            l.data[j * n + j] = root;
            for i in j + 1..n {
                let value =
                    self.get(i, j) - dot(&l.data[i * n..i * n + j], &l.data[j * n..j * n + j]);
                l.data[i * n + j] = value / root;
            }
        }
        Some(l)
    }

    /// `Y` with `Y Lᵀ = self`, `l` lower triangular.
    fn right_solve_lt(&self, l: &Self) -> Self {
        let n = l.rows;
        let mut out = Self::zeros(self.rows, self.cols);
        for r in 0..self.rows {
            let row = &mut out.data[r * n..(r + 1) * n];
            for i in 0..n {
                let value =
                    self.data[r * self.cols + i] - dot(&l.data[i * n..i * n + i], &row[..i]);
                row[i] = value / l.data[i * n + i];
            }
        }
        out
    }

    /// `Y` with `Y L = self`, `l` lower triangular.
    fn right_solve_l(&self, l: &Self) -> Self {
        let n = l.rows;
        // Lᵀ's rows are L's columns: contiguous for the dot products.
        let lt = l.transpose();
        let mut out = Self::zeros(self.rows, self.cols);
        for r in 0..self.rows {
            let row = &mut out.data[r * n..(r + 1) * n];
            for i in (0..n).rev() {
                let value = self.data[r * self.cols + i]
                    - dot(&lt.data[i * n + i + 1..(i + 1) * n], &row[i + 1..]);
                row[i] = value / lt.data[i * n + i];
            }
        }
        out
    }

    /// `L⁻ᵀ` of a lower triangular `l`.
    fn inverse_transpose_of_lower(l: &Self) -> Self {
        let n = l.rows;
        // L⁻¹ by forward substitution, column by column, then transposed.
        let mut inverse = Self::zeros(n, n);
        for c in 0..n {
            for i in c..n {
                let mut value = if i == c { 1.0 } else { 0.0 };
                for k in c..i {
                    value -= l.get(i, k) * inverse.get(k, c);
                }
                inverse.set(i, c, value / l.get(i, i));
            }
        }
        inverse.transpose()
    }

    fn symmetrise(&mut self) {
        for r in 0..self.rows {
            for c in r + 1..self.cols {
                let mean = 0.5 * (self.get(r, c) + self.get(c, r));
                self.set(r, c, mean);
                self.set(c, r, mean);
            }
        }
    }
}

/// `Σ a_i b_i` in one fixed order: four running sums over the chunks of four, added in order,
/// then the rest, so the same inputs give the same bits.
fn dot(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len().min(b.len());
    let (mut s0, mut s1, mut s2, mut s3) = (0.0, 0.0, 0.0, 0.0);
    let chunks = n / 4;
    for c in 0..chunks {
        let i = 4 * c;
        s0 += a[i] * b[i];
        s1 += a[i + 1] * b[i + 1];
        s2 += a[i + 2] * b[i + 2];
        s3 += a[i + 3] * b[i + 3];
    }
    let mut sum = (s0 + s1) + (s2 + s3);
    for i in 4 * chunks..n {
        sum += a[i] * b[i];
    }
    sum
}

/// Where a variable sits: a slice and the position in it, or the border.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum At {
    Slice(usize, usize),
    Border(usize),
}

/// A symmetric matrix in block-banded arrow form. Only the lower blocks are held: `lower[i][d]`
/// is block (i, i - d), `edge[i]` is the border rows against slice i, `corner` the border itself.
#[derive(Clone, Debug, PartialEq)]
pub struct Banded {
    pub sizes: Vec<usize>,
    pub border: usize,
    lower: Vec<Vec<Block>>,
    edge: Vec<Block>,
    corner: Block,
}

impl Banded {
    pub fn zeros(sizes: Vec<usize>, border: usize) -> Self {
        let lower = (0..sizes.len())
            .map(|i| {
                (0..=BAND.min(i))
                    .map(|d| Block::zeros(sizes[i], sizes[i - d]))
                    .collect()
            })
            .collect();
        let edge = sizes
            .iter()
            .map(|size| Block::zeros(border, *size))
            .collect();
        Self {
            sizes,
            border,
            lower,
            edge,
            corner: Block::zeros(border, border),
        }
    }

    /// Adds `value` to entry (a, b) and, by symmetry, (b, a). False when the two are not within
    /// the band (the caller's layout is wrong).
    pub fn add(&mut self, a: At, b: At, value: f64) -> bool {
        let (high, low) = if a >= b { (a, b) } else { (b, a) };
        match (high, low) {
            (At::Border(i), At::Border(j)) => {
                self.corner.add(i, j, value);
                if i != j {
                    self.corner.add(j, i, value);
                }
                true
            }
            (At::Border(i), At::Slice(s, r)) => {
                self.edge[s].add(i, r, value);
                true
            }
            (At::Slice(si, ri), At::Slice(sj, rj)) => {
                let d = si - sj;
                if d > BAND {
                    return false;
                }
                self.lower[si][d].add(ri, rj, value);
                if d == 0 && ri != rj {
                    self.lower[si][0].add(rj, ri, value);
                }
                true
            }
            (At::Slice(..), At::Border(_)) => false,
        }
    }

    /// Adds the symmetric `m x m` matrix `values` (row major, only the upper triangle read) on the
    /// places `at`, which are ascending and distinct: entry `(i, j)` to `(at[i], at[j])` and its
    /// mirror. False when two places are not within the band.
    pub fn add_dense(&mut self, at: &[At], values: &[f64]) -> bool {
        let m = at.len();
        for i in 0..m {
            for j in i..m {
                let value = values[i * m + j];
                if value == 0.0 {
                    continue;
                }
                // `at` ascends, so `at[j]` is the later place.
                match (at[j], at[i]) {
                    (At::Slice(sj, rj), At::Slice(si, ri)) => {
                        let d = sj - si;
                        if d > BAND {
                            return false;
                        }
                        let block = &mut self.lower[sj][d];
                        block.data[rj * block.cols + ri] += value;
                        if d == 0 && ri != rj {
                            block.data[ri * block.cols + rj] += value;
                        }
                    }
                    (At::Border(bj), At::Slice(si, ri)) => {
                        let block = &mut self.edge[si];
                        block.data[bj * block.cols + ri] += value;
                    }
                    (At::Border(bj), At::Border(bi)) => {
                        let n = self.border;
                        self.corner.data[bj * n + bi] += value;
                        if bi != bj {
                            self.corner.data[bi * n + bj] += value;
                        }
                    }
                    (At::Slice(..), At::Border(_)) => return false,
                }
            }
        }
        true
    }

    /// The `m x m` matrix of entries on the places `at` (ascending and distinct), full and
    /// symmetric; an entry outside the stored pattern is zero.
    pub fn gather(&self, at: &[At]) -> Vec<f64> {
        let m = at.len();
        let mut out = vec![0.0; m * m];
        for i in 0..m {
            for j in i..m {
                let value = match (at[j], at[i]) {
                    (At::Slice(sj, rj), At::Slice(si, ri)) => {
                        let d = sj - si;
                        if d > BAND {
                            0.0
                        } else {
                            let block = &self.lower[sj][d];
                            block.data[rj * block.cols + ri]
                        }
                    }
                    (At::Border(bj), At::Slice(si, ri)) => {
                        let block = &self.edge[si];
                        block.data[bj * block.cols + ri]
                    }
                    (At::Border(bj), At::Border(bi)) => self.corner.data[bj * self.border + bi],
                    (At::Slice(..), At::Border(_)) => 0.0,
                };
                out[i * m + j] = value;
                out[j * m + i] = value;
            }
        }
        out
    }

    /// Entry (a, b), or `None` outside the stored pattern.
    pub fn get(&self, a: At, b: At) -> Option<f64> {
        let (high, low, swapped) = if a >= b { (a, b, false) } else { (b, a, true) };
        let _ = swapped;
        match (high, low) {
            (At::Border(i), At::Border(j)) => Some(self.corner.get(i, j)),
            (At::Border(i), At::Slice(s, r)) => Some(self.edge[s].get(i, r)),
            (At::Slice(si, ri), At::Slice(sj, rj)) => {
                let d = si - sj;
                (d <= BAND).then(|| self.lower[si][d].get(ri, rj))
            }
            (At::Slice(..), At::Border(_)) => None,
        }
    }

    /// The block Cholesky factor, in the fixed order: slices first to last, then the border.
    pub fn factor(&self) -> Option<Factor> {
        let n = self.sizes.len();
        let mut lower: Vec<Vec<Block>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut row: Vec<Block> = (0..=BAND.min(i))
                .map(|d| self.lower[i][d].clone())
                .collect();
            for d in (1..=BAND.min(i)).rev() {
                let j = i - d;
                // Subtract L[i][k] L[j][k]ᵀ over the k both reach: k = i - e, e > d.
                for e in d + 1..=BAND.min(i) {
                    let (left, right) = (&row[e].clone(), &lower[j][e - d]);
                    row[d].sub_mul_t(left, right);
                }
                row[d] = row[d].right_solve_lt(&lower[j][0]);
            }
            // Only the lower triangle: all the factor reads.
            let mut diagonal = row[0].clone();
            for block in &row[1..=BAND.min(i)] {
                diagonal.sub_mul_t_lower(block);
            }
            row[0] = diagonal.cholesky()?;
            lower.push(row);
        }
        let mut edge: Vec<Block> = Vec::with_capacity(n);
        for i in 0..n {
            let mut block = self.edge[i].clone();
            for d in 1..=BAND.min(i) {
                block.sub_mul_t(&edge[i - d], &lower[i][d]);
            }
            edge.push(block.right_solve_lt(&lower[i][0]));
        }
        let mut corner = self.corner.clone();
        for block in &edge {
            corner.sub_mul_t_lower(block);
        }
        let corner = if self.border == 0 {
            corner
        } else {
            corner.cholesky()?
        };
        Some(Factor {
            sizes: self.sizes.clone(),
            border: self.border,
            lower,
            edge,
            corner,
        })
    }
}

/// `M = L Lᵀ` in the same arrow form.
#[derive(Clone, Debug)]
pub struct Factor {
    sizes: Vec<usize>,
    border: usize,
    lower: Vec<Vec<Block>>,
    edge: Vec<Block>,
    corner: Block,
}

/// A vector laid out as the matrix is: per slice, then the border.
#[derive(Clone, Debug, PartialEq)]
pub struct Vector {
    pub slices: Vec<Vec<f64>>,
    pub border: Vec<f64>,
}

impl Vector {
    pub fn zeros(sizes: &[usize], border: usize) -> Self {
        Self {
            slices: sizes.iter().map(|size| vec![0.0; *size]).collect(),
            border: vec![0.0; border],
        }
    }

    pub fn get(&self, at: At) -> f64 {
        match at {
            At::Slice(s, r) => self.slices[s][r],
            At::Border(i) => self.border[i],
        }
    }

    pub fn add(&mut self, at: At, value: f64) {
        match at {
            At::Slice(s, r) => self.slices[s][r] += value,
            At::Border(i) => self.border[i] += value,
        }
    }

    pub fn dot(&self, other: &Self) -> f64 {
        let mut sum = 0.0;
        for (a, b) in self.slices.iter().zip(&other.slices) {
            for (x, y) in a.iter().zip(b) {
                sum += x * y;
            }
        }
        for (x, y) in self.border.iter().zip(&other.border) {
            sum += x * y;
        }
        sum
    }
}

fn lower_solve(l: &Block, b: &[f64]) -> Vec<f64> {
    let mut y = vec![0.0; l.rows];
    for i in 0..l.rows {
        let mut value = b[i];
        for k in 0..i {
            value -= l.get(i, k) * y[k];
        }
        y[i] = value / l.get(i, i);
    }
    y
}

fn upper_solve(l: &Block, y: &[f64]) -> Vec<f64> {
    let mut x = vec![0.0; l.rows];
    for i in (0..l.rows).rev() {
        let mut value = y[i];
        for k in i + 1..l.rows {
            value -= l.get(k, i) * x[k];
        }
        x[i] = value / l.get(i, i);
    }
    x
}

impl Factor {
    /// `x` with `M x = b`.
    pub fn solve(&self, b: &Vector) -> Vector {
        let n = self.sizes.len();
        let mut y: Vec<Vec<f64>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut value = b.slices[i].clone();
            for d in 1..=BAND.min(i) {
                let block = &self.lower[i][d];
                for r in 0..block.rows {
                    for c in 0..block.cols {
                        value[r] -= block.get(r, c) * y[i - d][c];
                    }
                }
            }
            y.push(lower_solve(&self.lower[i][0], &value));
        }
        let mut border = b.border.clone();
        for (i, block) in self.edge.iter().enumerate() {
            for r in 0..block.rows {
                for c in 0..block.cols {
                    border[r] -= block.get(r, c) * y[i][c];
                }
            }
        }
        let y_border = if self.border == 0 {
            Vec::new()
        } else {
            lower_solve(&self.corner, &border)
        };
        let x_border = if self.border == 0 {
            Vec::new()
        } else {
            upper_solve(&self.corner, &y_border)
        };
        let mut x: Vec<Vec<f64>> = vec![Vec::new(); n];
        for i in (0..n).rev() {
            let mut value = y[i].clone();
            for d in 1..=BAND {
                if i + d >= n {
                    break;
                }
                let block = &self.lower[i + d][d];
                for r in 0..block.rows {
                    for c in 0..block.cols {
                        value[c] -= block.get(r, c) * x[i + d][r];
                    }
                }
            }
            let block = &self.edge[i];
            for r in 0..block.rows {
                for c in 0..block.cols {
                    value[c] -= block.get(r, c) * x_border[r];
                }
            }
            x[i] = upper_solve(&self.lower[i][0], &value);
        }
        Vector {
            slices: x,
            border: x_border,
        }
    }

    /// The inverse's blocks inside the factor's pattern (the band and the border), by
    /// Takahashi's recurrence `Z L = L⁻ᵀ`, last block first: for a block below the diagonal
    /// `Z[r][i] = -Σ Z[r][q] L[q][i] L[i][i]⁻¹`, and on it
    /// `Z[i][i] = (L[i][i]⁻ᵀ - Σ Z[i][q] L[q][i]) L[i][i]⁻¹`, `q` over the blocks below `i` in
    /// its column. Every `Z[r][q]` those need is itself inside the pattern.
    pub fn selected_inverse(&self) -> Banded {
        let n = self.sizes.len();
        let mut z = Banded::zeros(self.sizes.clone(), self.border);
        if self.border > 0 {
            let mut corner = Block::inverse_transpose_of_lower(&self.corner);
            corner = corner.right_solve_l(&self.corner);
            corner.symmetrise();
            z.corner = corner;
        }
        for i in (0..n).rev() {
            // The blocks below slice i in its column: slices i + 1 ..= i + BAND, then the border.
            let below: Vec<usize> = (1..=BAND).filter(|d| i + d < n).collect();
            // Z[r][q] for r, q in that set, as full blocks (rows r, columns q).
            let zz = |z: &Banded, r: Option<usize>, q: Option<usize>| -> Block {
                match (r, q) {
                    (None, None) => z.corner.clone(),
                    (None, Some(q)) => z.edge[q].clone(),
                    (Some(r), None) => z.edge[r].transpose(),
                    (Some(r), Some(q)) => {
                        if r >= q {
                            z.lower[r][r - q].clone()
                        } else {
                            z.lower[q][q - r].transpose()
                        }
                    }
                }
            };
            // L[q][i] for q in the set.
            let l_below = |q: Option<usize>| -> Block {
                match q {
                    None => self.edge[i].clone(),
                    Some(q) => self.lower[q][q - i].clone(),
                }
            };
            let rows: Vec<Option<usize>> = below
                .iter()
                .map(|d| Some(i + d))
                .chain((self.border > 0).then_some(None))
                .collect();
            let mut new: Vec<(Option<usize>, Block)> = Vec::with_capacity(rows.len());
            for r in &rows {
                let size = r.map_or(self.border, |r| self.sizes[r]);
                let mut sum = Block::zeros(size, self.sizes[i]);
                for q in &rows {
                    sum.add_mul(&zz(&z, *r, *q), &l_below(*q));
                }
                let mut value = sum.right_solve_l(&self.lower[i][0]);
                value.data.iter_mut().for_each(|x| *x = -*x);
                new.push((*r, value));
            }
            // The diagonal block, from the new off-diagonal blocks.
            let mut diagonal = Block::inverse_transpose_of_lower(&self.lower[i][0]);
            for (q, block) in &new {
                // Z[i][q] L[q][i], Z[i][q] = Z[q][i]ᵀ.
                let mut product = Block::zeros(self.sizes[i], self.sizes[i]);
                product.add_mul(&block.transpose(), &l_below(*q));
                for (value, minus) in diagonal.data.iter_mut().zip(&product.data) {
                    *value -= minus;
                }
            }
            let mut diagonal = diagonal.right_solve_l(&self.lower[i][0]);
            diagonal.symmetrise();
            for (r, block) in new {
                match r {
                    None => z.edge[i] = block,
                    Some(r) => z.lower[r][r - i] = block,
                }
            }
            z.lower[i][0] = diagonal;
        }
        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linalg::Matrix;
    use crate::sim::Rng;

    /// Every variable's place, in the order the dense reference numbers them.
    fn places(sizes: &[usize], border: usize) -> Vec<At> {
        let mut out = Vec::new();
        for (s, size) in sizes.iter().enumerate() {
            for r in 0..*size {
                out.push(At::Slice(s, r));
            }
        }
        for b in 0..border {
            out.push(At::Border(b));
        }
        out
    }

    /// A random positive definite matrix with the band and arrow pattern, as both forms.
    fn random(rng: &mut Rng, sizes: &[usize], border: usize) -> (Banded, Matrix) {
        let at = places(sizes, border);
        let n = at.len();
        let mut banded = Banded::zeros(sizes.to_vec(), border);
        let mut dense = Matrix::zeros(n);
        // A sum of rank-one terms over variables that may be coupled, plus a diagonal.
        for _ in 0..4 * n {
            let start = (rng.next_u64() % sizes.len() as u64) as usize;
            let chosen: Vec<usize> = (0..n)
                .filter(|index| match at[*index] {
                    At::Slice(s, _) => s >= start && s <= start + BAND,
                    At::Border(_) => true,
                })
                .filter(|_| rng.uniform() < 0.5)
                .collect();
            let values: Vec<f64> = chosen.iter().map(|_| rng.normal()).collect();
            for (a, va) in chosen.iter().zip(&values) {
                for (b, vb) in chosen.iter().zip(&values) {
                    if a >= b {
                        let value = va * vb;
                        assert!(banded.add(at[*a], at[*b], value));
                        dense.add(*a, *b, value);
                        if a != b {
                            dense.add(*b, *a, value);
                        }
                    }
                }
            }
        }
        for index in 0..n {
            banded.add(at[index], at[index], 0.5);
            dense.add(index, index, 0.5);
        }
        (banded, dense)
    }

    fn close(a: f64, b: f64, scale: f64) -> bool {
        (a - b).abs() <= 1e-12 * scale.max(1.0)
    }

    #[test]
    fn the_banded_factor_solves_and_selectively_inverts_as_the_dense_one_does() -> Result<(), String>
    {
        let mut rng = Rng::new(3);
        for (sizes, border) in [
            (vec![3, 2, 4, 3, 1, 3], 2),
            (vec![2, 2], 0),
            (vec![1], 3),
            (vec![4, 3, 3, 3, 4, 2, 3, 2], 5),
        ] {
            let (banded, dense) = random(&mut rng, &sizes, border);
            let at = places(&sizes, border);
            let n = at.len();
            let factor = banded.factor().ok_or("not positive definite")?;
            let reference = dense.cholesky().ok_or("not positive definite")?;
            let b: Vec<f64> = (0..n).map(|_| rng.normal()).collect();
            let mut vector = Vector::zeros(&sizes, border);
            for (index, place) in at.iter().enumerate() {
                vector.add(*place, b[index]);
            }
            let x = factor.solve(&vector);
            let want = reference.solve(&b);
            let scale = want.iter().fold(0.0f64, |m, v| m.max(v.abs()));
            for (index, place) in at.iter().enumerate() {
                assert!(
                    close(x.get(*place), want[index], scale),
                    "solve at {place:?}"
                );
            }
            let z = factor.selected_inverse();
            let inverse = reference.inverse();
            let scale = inverse.data.iter().fold(0.0f64, |m, v| m.max(v.abs()));
            let mut compared = 0;
            for (i, a) in at.iter().enumerate() {
                for (j, b) in at.iter().enumerate() {
                    if let Some(value) = z.get(*a, *b) {
                        assert!(
                            close(value, inverse.get(i, j), scale),
                            "{a:?} {b:?}: {value} against {}",
                            inverse.get(i, j)
                        );
                        compared += 1;
                    }
                }
            }
            assert!(compared > 0);
        }
        Ok(())
    }

    #[test]
    fn an_indefinite_matrix_is_refused() {
        let mut banded = Banded::zeros(vec![2], 0);
        banded.add(At::Slice(0, 0), At::Slice(0, 0), 1.0);
        banded.add(At::Slice(0, 1), At::Slice(0, 1), -1.0);
        assert!(banded.factor().is_none());
    }
}
