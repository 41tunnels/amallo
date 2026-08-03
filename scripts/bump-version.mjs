#!/usr/bin/env node
// Called from semantic-release's @semantic-release/exec "prepareCmd"
// (see .releaserc.json) with the version it just computed from
// conventional commits. Keeps every file that actually embeds a version
// number in sync with that release: package.json (npm metadata) and
// tauri.conf.json + Cargo.toml (what ends up in the built app/installer).
//
// Cargo.lock's own entry for this package is left alone on purpose —
// cargo rewrites it to match Cargo.toml as an ordinary side effect of the
// next `cargo build`/`check` (which the release workflow's build job
// does anyway), so there is nothing to keep in sync by hand here.
import { readFileSync, writeFileSync } from 'node:fs'

const version = process.argv[2]
if (!version) {
  console.error('usage: bump-version.mjs <version>')
  process.exit(1)
}

function bumpJson(path, mutate) {
  const data = JSON.parse(readFileSync(path, 'utf8'))
  mutate(data)
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n')
}

bumpJson('package.json', (data) => {
  data.version = version
})

bumpJson('src-tauri/tauri.conf.json', (data) => {
  data.version = version
})

const cargoTomlPath = 'src-tauri/Cargo.toml'
const cargoToml = readFileSync(cargoTomlPath, 'utf8')
// Anchored to the [package] section specifically, not a bare
// `/^version = /` pattern — Cargo.toml's [dependencies] section is full
// of other crates' own `version = "..."` lines.
const versionFieldPattern = /(\[package\][\s\S]*?\nversion\s*=\s*)"[^"]*"/
// Checked via .test() before replacing, not by comparing the before/after
// strings — a before/after comparison is a false positive whenever the
// target version happens to already be what's on disk (e.g. re-running
// after a release's tag was deleted and recomputed to the same version):
// the replace still matches and "succeeds", it just produces a string
// identical to the input, which a before/after check would misreport as
// "no match found".
if (!versionFieldPattern.test(cargoToml)) {
  console.error(`could not find [package]'s version field in ${cargoTomlPath}`)
  process.exit(1)
}
const updated = cargoToml.replace(versionFieldPattern, `$1"${version}"`)
writeFileSync(cargoTomlPath, updated)

console.log(`bumped to ${version}`)
