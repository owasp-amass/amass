# Contributing

Thank you for considering making contributions to Amass! Start by taking a look at the [open issues](https://github.com/owasp-amass/amass/issues) for things we need help with!

Please follow standard github best practices: fork the repo, branch from the tip of develop, make some commits, and submit a pull request to develop. 

Please make sure to use `gofmt` before every commit - the easiest way to do this is have your editor run it for you upon saving a file. Otherwise, run the following command in the project root directory: `go fmt ./...`

## Forking

Please note that Go requires code to live under absolute paths, which complicates forking.
While the fork for user 'foo' lives at `https://github.com/foo/amass`,
the code should never exist at  `$GOPATH/src/github.com/foo/amass`.
Instead, we use `git remote` to add the fork as a new remote for the original repo,
`$GOPATH/src/github.com/owasp-amass/amass`, and do all the work there.

For instance, to create a fork and work on a branch of it, user 'foo' would:

  * Create the fork on github, using the fork button.
  * Go to the original repo checked out locally (ie. `$GOPATH/src/github.com/owasp-amass/amass`)
  * `git remote rename origin upstream`
  * `git remote add origin git@github.com:foo/amass.git`

Now `origin` refers to the foo fork and `upstream` refers to the OWASP version.
So foo can `git push -u origin master` to update his/her fork, and make pull requests to OWASP from there.
Of course, replace `foo` with your git handle.

To pull in updates from the original repo, run

    * `git fetch upstream`
    * `git rebase upstream/master` (or whatever branch you want)

Please don't make Pull Requests to `master`.

### Development Procedure:
- the latest state of development is on `develop`
- no --force onto `develop` (except when reverting a broken commit, which should seldom happen)
- create a development branch on your fork (using `git add origin`)
- before submitting a pull request, begin `git rebase` on top of `develop`
