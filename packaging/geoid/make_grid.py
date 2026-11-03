#!/usr/bin/env python3
"""Build the compact EGM2008 geoid grid (geoid.txt) for the Tally installer.

Source: PROJ CDN, https://cdn.proj.org/us_nga_egm08_25.tif
  NGA EGM2008 geoid undulation N (metres above the WGS84 ellipsoid), 2.5
  arc-minute, PixelIsPoint, 4321 rows lat 90..-90, 8640 cols lon -180..179.958
  sha256 4191d471eefebf24091b56dbc604353cb3b8cf8cc70e448bb9ae56a272bef17a
  EGM2008 is published by the US National Geospatial-Intelligence Agency
  without restriction (public domain); PROJ redistributes it.

Grid: a global base grid (BASE degrees) point-sampled from the fine grid,
plus, over land only, finer patch nodes where the base grid's bicubic
interpolation error exceeds THR metres somewhere in a base cell. For each such
cell the generator picks the coarsest of LEVELS (arc-minutes) whose bicubic
error over the cell's land nodes is <= THR and emits every node that bicubic
interpolation inside the cell needs (cell nodes plus a one-node margin).
Land: global_land_mask (1 km, GLOBE-derived). Values: integer decimetres.

File format (text): '#' comment lines; '# levels A B ...' lists node spacings
in arc-minutes, coarsest (the global base) first; every data line is
  STEP_ARCMIN ROW COL0 V0 D1 D2 ...
meaning the nodes ROW, COL0.. of the STEP grid (row 0 = lat 90, col 0 =
lon -180, row r = lat 90 - r*step, col c = lon -180 + c*step, cols wrap)
have values V0, V0+D1, V0+D1+D2, ... dm (delta-coded along the row), and
  A STEP_ARCMIN BROW BCOL0 COUNT
marks base cells BROW, BCOL0..BCOL0+COUNT-1 (cell = nodes BROW..BROW+1,
BCOL..BCOL+1 of the base grid) as interpolated on the STEP patch grid; the
file holds every patch node that bicubic interpolation in those cells needs.

Usage: python3 -I make_grid.py SOURCE.tif OUT.txt [BASE_DEG [THR_M [LEVELS]]]
  defaults (the shipped geoid.txt): BASE_DEG 2, THR_M 2, LEVELS "60,30,15,10,5" (arc-minutes);
  THR_M 0 or LEVELS "" gives a plain uniform grid.
Requires numpy, tifffile, imagecodecs, global_land_mask.
"""
import hashlib, sys
import numpy as np
import tifffile

SRC_URL = "https://cdn.proj.org/us_nga_egm08_25.tif"
SRC_SHA256 = "4191d471eefebf24091b56dbc604353cb3b8cf8cc70e448bb9ae56a272bef17a"
FINE_MIN = 2.5  # arc-minutes


def keys(t):
    return [((-0.5 * t + 1) * t - 0.5) * t, (1.5 * t - 2.5) * t * t + 1,
            ((-1.5 * t + 2) * t + 0.5) * t, (0.5 * t - 0.5) * t * t]


def uniform_bicubic_abs_err(fine, step):
    """|bicubic(step-grid in dm) - fine| at every fine node, pole rows reflected."""
    R1, C1 = fine.shape
    g = np.rint(fine[::step, ::step] * 10) / 10
    R, C = g.shape
    jj = np.arange(C1); j0 = jj // step; fx = (jj % step) / step
    ii = np.arange(R1); i0 = np.minimum(ii // step, R - 2); fy = (ii - i0 * step) / step
    ext = np.vstack([np.roll(g[1:2], C // 2, 1), g, np.roll(g[R - 2:R - 1], C // 2, 1),
                     np.roll(g[R - 3:R - 2], C // 2, 1)])  # rows -1 .. R+1
    wx, wy = keys(fx), keys(fy)
    A = sum(wx[b][None, :] * ext[:, (j0 - 1 + b) % C] for b in range(4))
    est = sum(wy[a][:, None] * A[i0 + a, :] for a in range(4))
    return np.abs(est - fine)


def canon(r, c, R, C):
    """Map a possibly over-the-pole node to its canonical (row, col)."""
    if r < 0:
        r, c = -r, c + C // 2
    elif r > R - 1:
        r, c = 2 * (R - 1) - r, c + C // 2
    return r, c % C


def main():
    src, out = sys.argv[1], sys.argv[2]
    base = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
    thr = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0
    lv = sys.argv[5] if len(sys.argv) > 5 else "60,30,15,10,5"
    levels = [float(x) for x in lv.split(",") if x] if thr > 0 else []
    h = hashlib.sha256()
    with open(src, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    if h.hexdigest() != SRC_SHA256:
        sys.exit("sha256 mismatch: %s" % h.hexdigest())
    with tifffile.TiffFile(src) as t:
        pg = t.pages[0]
        assert abs(pg.tags["ModelPixelScaleTag"].value[0] - FINE_MIN / 60) < 1e-12
        assert tuple(pg.tags["ModelTiepointTag"].value[3:5]) == (-180.0, 90.0)
        fine = pg.asarray().astype(np.float64)
    assert fine.shape == (4321, 8640)
    R1, C1 = fine.shape
    bstep = round(base * 60 / FINE_MIN)
    steps = [round(L / FINE_MIN) for L in levels]
    assert all(bstep % s == 0 for s in steps)
    lines = []

    def emit(step, r, cols, R):  # cols: sorted canonical column indices on row r
        vals = np.rint(fine[r * step, np.array(cols) * step] * 10).astype(int)
        runs, start = [], 0
        for k in range(1, len(cols) + 1):
            if k == len(cols) or cols[k] != cols[k - 1] + 1:
                runs.append((start, k)); start = k
        for a, b in runs:
            v = vals[a:b]
            lines.append("%g %d %d %d%s" % (step * FINE_MIN, r, cols[a], v[0],
                         "".join(" %d" % d for d in np.diff(v))))

    RB, CB = R1 // bstep + 1, C1 // bstep
    for r in range(RB):
        emit(bstep, r, list(range(CB)), RB)
    stats = {}
    cells = []
    if levels:
        from global_land_mask import globe
        lat1 = 90 - np.arange(R1) * FINE_MIN / 60
        lon1 = -180 + np.arange(C1) * FINE_MIN / 60
        land = globe.is_land(np.clip(lat1, -89.99, 89.99)[:, None] * np.ones((1, C1)),
                             np.clip(lon1, -179.99, 179.99)[None, :] * np.ones((R1, 1)))[:R1 - 1]
        nb, mb = (R1 - 1) // bstep, C1 // bstep

        def cellmax(step):
            e = np.where(land, uniform_bicubic_abs_err(fine, step)[:R1 - 1], 0)
            return e.reshape(nb, bstep, mb, bstep).max(axis=(1, 3))
        hasland = land.reshape(nb, bstep, mb, bstep).any(axis=(1, 3))
        todo = hasland & (cellmax(bstep) > thr)
        for k, step in enumerate(steps):
            cm = cellmax(step)
            assigned = todo & ((cm <= thr) | (k == len(steps) - 1))
            todo &= ~assigned
            stats[levels[k]] = int(assigned.sum())
            for i in range(nb):
                js = np.nonzero(assigned[i])[0]
                if len(js) == 0: continue
                brk = np.nonzero(np.diff(js) != 1)[0] + 1
                for run in np.split(js, brk):
                    cells.append("A %g %d %d %d" % (levels[k], i, run[0], len(run)))
            m = bstep // step
            R, C = (R1 - 1) // step + 1, C1 // step
            need = {}
            for i, j in zip(*np.nonzero(assigned)):
                for r in range(i * m - 1, i * m + m + 2):
                    for c in range(j * m - 1, j * m + m + 2):
                        rr, cc = canon(r, c, R, C)
                        need.setdefault(rr, set()).add(cc)
            for r in sorted(need):
                emit(step, r, sorted(need[r]), R)
    with open(out, "w") as f:
        f.write("# EGM2008 geoid undulation N = WGS84 ellipsoidal height minus EGM2008 "
                "orthometric height; integer decimetres; node lat = 90 - row*step, "
                "lon = -180 + col*step (wraps)\n")
        f.write("# source: NGA EGM2008 (public domain) via %s sha256 %s\n" % (SRC_URL, SRC_SHA256))
        f.write("# built by make_grid.py base %g deg, land patches where bicubic error > %g m, "
                "patch cells per level %s\n" % (base, thr, stats))
        f.write("# data lines: STEP_ARCMIN ROW COL0 V0 D1 D2 ... (values V0, V0+D1, ...); "
                "A STEP_ARCMIN BASE_ROW BASE_COL0 COUNT = base cells using that patch level\n")
        f.write("# levels %s\n" % " ".join("%g" % x for x in [base * 60] + levels))
        f.write("\n".join(cells + lines) + "\n")


if __name__ == "__main__":
    main()
