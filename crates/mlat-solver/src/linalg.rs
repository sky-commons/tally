//! Dense linear algebra over `f64`, written out so every operation happens in one fixed order
//! (no SIMD reassociation, no threads): the same inputs give the same bits.
//!
//! Matrices are row major in a `Vec<f64>` of `n * n`. Only symmetric positive definite systems are
//! solved, by Cholesky; a matrix that is not positive definite is refused, never regularised
//! silently.

/// A square matrix, row major.
#[derive(Clone, Debug, PartialEq)]
pub struct Matrix {
    pub n: usize,
    pub data: Vec<f64>,
}

impl Matrix {
    pub fn zeros(n: usize) -> Self {
        Self {
            n,
            data: vec![0.0; n * n],
        }
    }

    pub fn get(&self, row: usize, column: usize) -> f64 {
        self.data[row * self.n + column]
    }

    pub fn set(&mut self, row: usize, column: usize, value: f64) {
        self.data[row * self.n + column] = value;
    }

    pub fn add(&mut self, row: usize, column: usize, value: f64) {
        self.data[row * self.n + column] += value;
    }

    /// The Cholesky factor `L` (lower triangular, `A = L Lᵀ`), or `None` when the matrix is not
    /// positive definite to working precision.
    pub fn cholesky(&self) -> Option<Cholesky> {
        let n = self.n;
        let mut l = vec![0.0; n * n];
        for j in 0..n {
            let mut diagonal = self.data[j * n + j];
            for k in 0..j {
                diagonal -= l[j * n + k] * l[j * n + k];
            }
            if diagonal.is_nan() || diagonal <= 0.0 {
                return None;
            }
            let root = diagonal.sqrt();
            l[j * n + j] = root;
            for i in j + 1..n {
                let mut value = self.data[i * n + j];
                for k in 0..j {
                    value -= l[i * n + k] * l[j * n + k];
                }
                l[i * n + j] = value / root;
            }
        }
        Some(Cholesky { n, l })
    }

    /// `self · inner · self` for a symmetric `self`: the covariance `inner` carried through the
    /// linear map `self`, symmetric by construction.
    pub fn sandwich(&self, inner: &Matrix) -> Matrix {
        let n = self.n;
        let mut half = vec![0.0; n * n];
        for i in 0..n {
            for j in 0..n {
                half[i * n + j] = (0..n)
                    .map(|k| self.data[i * n + k] * inner.data[k * n + j])
                    .sum();
            }
        }
        let mut out = Matrix::zeros(n);
        for i in 0..n {
            for j in 0..=i {
                let value: f64 = (0..n).map(|k| half[i * n + k] * self.data[k * n + j]).sum();
                out.set(i, j, value);
                out.set(j, i, value);
            }
        }
        out
    }

    /// `self · v`.
    pub fn mul_vec(&self, v: &[f64]) -> Vec<f64> {
        (0..self.n)
            .map(|row| {
                self.data[row * self.n..(row + 1) * self.n]
                    .iter()
                    .zip(v)
                    .map(|(a, b)| a * b)
                    .sum()
            })
            .collect()
    }
}

/// A Cholesky factorisation `A = L Lᵀ`.
#[derive(Clone, Debug)]
pub struct Cholesky {
    n: usize,
    l: Vec<f64>,
}

impl Cholesky {
    /// `x` with `A x = b`.
    pub fn solve(&self, b: &[f64]) -> Vec<f64> {
        let y = self.forward(b);
        self.backward(&y)
    }

    /// `y` with `L y = b`.
    pub fn forward(&self, b: &[f64]) -> Vec<f64> {
        let n = self.n;
        let mut y = vec![0.0; n];
        for i in 0..n {
            let mut value = b[i];
            for k in 0..i {
                value -= self.l[i * n + k] * y[k];
            }
            y[i] = value / self.l[i * n + i];
        }
        y
    }

    /// `R` with `L R = Q`, `Q` (and `R`) row-major with `width` columns.
    pub fn forward_rows(&self, q: &[f64], width: usize) -> Vec<f64> {
        let n = self.n;
        let mut r = q.to_vec();
        for i in 0..n {
            for k in 0..i {
                let factor = self.l[i * n + k];
                if factor == 0.0 {
                    continue;
                }
                for j in 0..width {
                    r[i * width + j] -= factor * r[k * width + j];
                }
            }
            let root = self.l[i * n + i];
            for value in &mut r[i * width..(i + 1) * width] {
                *value /= root;
            }
        }
        r
    }

    /// `x` with `Lᵀ x = y`.
    pub fn backward(&self, y: &[f64]) -> Vec<f64> {
        let n = self.n;
        let mut x = vec![0.0; n];
        for i in (0..n).rev() {
            let mut value = y[i];
            for k in i + 1..n {
                value -= self.l[k * n + i] * x[k];
            }
            x[i] = value / self.l[i * n + i];
        }
        x
    }

    /// `L⁻¹`, lower triangular, row by row.
    fn lower_inverse(&self) -> Vec<f64> {
        let n = self.n;
        let mut inv = vec![0.0; n * n];
        for i in 0..n {
            let root = self.l[i * n + i];
            inv[i * n + i] = 1.0 / root;
            for j in 0..i {
                let mut value = 0.0;
                for k in j..i {
                    value -= self.l[i * n + k] * inv[k * n + j];
                }
                inv[i * n + j] = value / root;
            }
        }
        inv
    }

    /// `A⁻¹`'s diagonal, as [`Cholesky::inverse_triangular`] makes it (the same sums in the same
    /// order) without the rest: half its work, for a caller that reads only the variances.
    pub fn inverse_diagonal(&self) -> Vec<f64> {
        let n = self.n;
        let inv = self.lower_inverse();
        (0..n)
            .map(|i| (i..n).map(|k| inv[k * n + i] * inv[k * n + i]).sum())
            .collect()
    }

    /// `A⁻¹` as `L⁻ᵀ L⁻¹`: a third of [`Cholesky::inverse`]'s work, symmetric by construction.
    pub fn inverse_triangular(&self) -> Matrix {
        let n = self.n;
        let inv = self.lower_inverse();
        let mut out = Matrix::zeros(n);
        for i in 0..n {
            for j in 0..=i {
                let value: f64 = (i..n).map(|k| inv[k * n + i] * inv[k * n + j]).sum();
                out.set(i, j, value);
                out.set(j, i, value);
            }
        }
        out
    }

    /// `A⁻¹`, column by column.
    pub fn inverse(&self) -> Matrix {
        let n = self.n;
        let mut inverse = Matrix::zeros(n);
        let mut unit = vec![0.0; n];
        for column in 0..n {
            unit.iter_mut().for_each(|value| *value = 0.0);
            unit[column] = 1.0;
            let x = self.solve(&unit);
            for (row, value) in x.into_iter().enumerate() {
                inverse.set(row, column, value);
            }
        }
        // Symmetrise exactly, so the stored covariance is symmetric to the bit.
        for row in 0..n {
            for column in row + 1..n {
                let mean = 0.5 * (inverse.get(row, column) + inverse.get(column, row));
                inverse.set(row, column, mean);
                inverse.set(column, row, mean);
            }
        }
        inverse
    }
}

pub type Vec3 = [f64; 3];

pub fn sub(a: Vec3, b: Vec3) -> Vec3 {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

pub fn dot(a: Vec3, b: Vec3) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

pub fn norm(a: Vec3) -> f64 {
    dot(a, a).sqrt()
}

pub fn scale(a: Vec3, k: f64) -> Vec3 {
    [a[0] * k, a[1] * k, a[2] * k]
}

pub fn add(a: Vec3, b: Vec3) -> Vec3 {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cholesky_solves_and_inverts() -> Result<(), String> {
        let a = Matrix {
            n: 3,
            data: vec![4.0, 12.0, -16.0, 12.0, 37.0, -43.0, -16.0, -43.0, 98.0],
        };
        let factor = a.cholesky().ok_or("not positive definite")?;
        let x = factor.solve(&[1.0, 2.0, 3.0]);
        let back = a.mul_vec(&x);
        for (got, want) in back.iter().zip([1.0, 2.0, 3.0]) {
            assert!((got - want).abs() < 1e-9);
        }
        let diagonal = factor.inverse_diagonal();
        let triangular = factor.inverse_triangular();
        for (at, value) in diagonal.iter().enumerate() {
            assert_eq!(value.to_bits(), triangular.get(at, at).to_bits());
        }
        for inverse in [factor.inverse(), triangular] {
            for row in 0..3 {
                for column in 0..3 {
                    let mut value = 0.0;
                    for k in 0..3 {
                        value += a.get(row, k) * inverse.get(k, column);
                    }
                    let want = if row == column { 1.0 } else { 0.0 };
                    assert!((value - want).abs() < 1e-9);
                    assert_eq!(inverse.get(row, column), inverse.get(column, row));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn an_indefinite_matrix_is_refused() {
        let a = Matrix {
            n: 2,
            data: vec![1.0, 2.0, 2.0, 1.0],
        };
        assert!(a.cholesky().is_none());
    }
}
