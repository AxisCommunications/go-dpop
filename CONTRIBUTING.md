# Contributing

Please use the github issue tracker for any bugs or feature requests,
email sent to the maintainer(s) will probably not be acted upon.

If you would like to contribute bug fixes or new components,
make sure there is an existing issue for it, and make a pull
request referencing the issue.

We use [conventional commits](https://www.conventionalcommits.org) to write commit messages.
If your changes cause problems with how the library was used before,
don't forget to write `BREAKING CHANGE:` inside the commit message body,
followed by a description of what has changed and how to adapt for it.

## Getting started

After cloning this repository, make sure you have go 1.20 or later installed.
Running `go test ./..` should indicate if your go installation is working correctly.

### Testing

Make sure your changes pass linting and unit testing locally to save time with your PR,
by running `go vet ./...` and `go test ./...`.
If you add a new feature, please write a new unit test to catch any future regressions.

Most components have unit tests, and basic proper behaviour is always
tested.
If you contribute a new component, please make sure it has appropriate
unit tests with sufficient coverage.

### Code formatting

To make sure tests don't fail on format problems, it's recommended to use a
golang plugin for you editor, or to run `go fmt ./...` before committing
any changes.

## Creating PRs

Whenever you want to apply your changes to the upstream repository,
you can create a pull request (PR). You can find general information
on making pull requests on GitHub.

When you are ready to push your changes,
make sure you include a proper version tag in your commit by running:

```sh
git tag -a v<semVer> -m "<change description>"
```

where you should select a version (`<semVer>`) based on if your changes introduce
(possible) breaking changes (`major`), new feature additions (`minor`),
or just fixes a bug (`patch`). This is in accordance with [module version numbering](https://go.dev/doc/modules/version-numbers)

## Continuous integration

### Verification

Automated tests are run on the `main` branch and pull requests with GitHub Actions,
for which the configuration can be found in the `.github/workflows/test.yml` file.
These tests always need to pass before a PR can be merged.
