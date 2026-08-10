# Contributing

## Branching policy

New features should always be contributed to the `main` branch first.
They may then be backported to release branches if appropriate.

Release branches should only be targeted directly with pull requests when
fixing release-specific bugs.

## What to contribute

Useful contributions include:

- New features (`main` branch only)
- Backports from `main`
- Bug fixes
- Documentation improvements
- Recipe or class fixes
- Test and compatibility updates

## Before opening a pull request

Please:

1. Make sure you are targeting the right branch.
2. Test the change on the intended Yocto branch.
3. Keep changes focused and easy to review.
4. Update README.md if behavior or configuration changes.

## Backporting guidance

If you are porting a change from `main` to a release branch:

- verify the original change still applies cleanly
- adjust for older syntax or build-system differences
- check for hidden dependencies on newer OpenEmbedded or Yocto features
- compare outputs to ensure the result stays predictable

## Commit messages

Write clear commit messages that explain:

- what changed
- why it changed
- which branch or Yocto release it applies to

## Reporting issues

If you find a problem, please include:

- Yocto release branch
- exact configuration used
- relevant build logs
- the SBOM output or error message, if available

## License

By contributing, you agree that your changes will be distributed under the same
license as the project.
