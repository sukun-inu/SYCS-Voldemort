# Third-party notices

The original source code, documentation, configuration, and assets in this
repository are licensed under the MIT License in [LICENSE](LICENSE), except
where a file says otherwise or is listed below. Third-party works retain their
own copyright notices and licenses; they are not relicensed under MIT.

## Files included in this repository

| Files | Upstream project and version | License | License text |
| --- | --- | --- | --- |
| `webapp/static/vendor/bootstrap/` | Bootstrap 5.3.3 | MIT | [LICENSES/Bootstrap-MIT.txt](LICENSES/Bootstrap-MIT.txt) |
| `webapp/static/vendor/bootstrap-icons/` | Bootstrap Icons 1.11.3 | MIT | [LICENSES/Bootstrap-Icons-MIT.txt](LICENSES/Bootstrap-Icons-MIT.txt) |
| `webapp/static/vendor/lightweight-charts/` | TradingView Lightweight Charts 5.2.1 | Apache-2.0 | [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) |

The corresponding minified files also retain their upstream headers. No
separate upstream `NOTICE` file is included in this repository.

## Runtime and build dependencies

The packages in `requirements.txt` are installed separately and are not
relicensed by this repository. Their licenses apply when they are installed or
redistributed, including in a Docker image. Before distributing a built image
or executable, generate and review a dependency notice/SBOM for the exact
installed versions.

In particular, `mutagen` is a GPL-2.0-or-later dependency. Its inclusion in a
redistributed application bundle can create obligations beyond this
repository's MIT license. Confirm the applicable obligations for the intended
distribution model, or replace it with a permissively licensed alternative.
