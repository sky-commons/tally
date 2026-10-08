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
        let inverse = factor.inverse();
        for row in 0..3 {
            for column in 0..3 {
                let mut value = 0.0;
                for k in 0..3 {
                    value += a.get(row, k) * inverse.get(k, column);
                }
                let want = if row == column { 1.0 } else { 0.0 };
                assert!((value - want).abs() < 1e-9);
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
