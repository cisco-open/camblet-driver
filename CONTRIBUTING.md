# Contributing to Wasm Kernel Module

Thank you for taking the time to start contributing! We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a bug
- Sending a PR to submit a fix
- Proposing new features
- Helping new users with issues they may encounter
- Becoming a maintainer

To get started:

- Support the development of this project and star this repo! :star:
- If you use Wasm Kernel Module in a production environment, add yourself to the list of [adopters](ADOPTERS.md). :metal:

## Contributing on GitHub

We use GitHub to host code, track issues or feature requests, and accept pull requests.

### Issues

We use GitHub issues to track bugs and problems. Report a bug by [opening a new issue](https://github.com/cisco-open/nasp-kernel-module/issues).

Please format your issues in such a way as to help others who might be facing similar challenges.
Give your issues meaningful titles, that offer context and help us and the community to understand and quickly ramp up on it.

Consider including the following in a bug report:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Provide sample code if you can.
- What you expected would happen
- What happened
- Notes (possibly including why you think this might be happening, or things you tried that didn't work)


We are grateful for any issues submitted.
Questions, feature requests, or ideas are all welcomed.
We will try to respond to your issues promptly, but please note that as the project is open-source, volunteers may offer help on a limited, goodwill basis.
Please be respectful of any help offered, and accept that the person you are requesting help from may not reside in your time zone.

### Pull requests

We are always happy to receive contributions via pull requests.

Wasm Kernel Module follows the standard GitHub pull request process:

Fork the repo, write your code, test your changes and submit a PR to the repo's `main` branch.
Following the pull request template, describe the change(s) you're proposing, including context about why the change(s) are being made, and an explanation of any feature usage or behavior changes.
The PR must pass the CI/CD checks (that include builds, tests, and linters - see below)
We'll do our best to review the PR as soon as we can, but please accept if it takes time to respond.

When working on a PR, consider these best practices:

- Write clear and meaningful commit messages.
- If you're fixing a bug or a smaller issue, squash your commits to help us maintain a clear git history.
- We prefer if you rebase your commits before submitting the PR.
- Explain the context of why you're making the changes to help reviewers.
- Before starting to work on a larger feature, contact the maintainers to ensure the work is in line with the product roadmap.

### Tests and linters

A pull request must pass all tests and linters of the project.
Running these on your local machine is as easy as running these two commands:

`make test`

and

`make lint`

## License

By contributing, you agree that your contributions will be dual licensed under both MIT and GPLv2 licenses.
