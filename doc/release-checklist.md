This is a checklist for doing Sequoia releases.

 0. Starting from origin/master, create a branch for the release.
 1. For all 'Cargo.toml's: Bump version = "XXX".
 2. For all 'Cargo.toml's: Bump documentation = "https://.../XXX/...".
 3. For all 'Cargo.toml's: Bump intra-workspace dependencies.
 4. Run 'make sanity-check-versions'.
 5. Run 'cargo update && make check'.
 6. Make a commit with the message "Release XXX.".
 7. Make a tag vXXX with the message "Release XXX." signed with an
    offline-key.
 8. Make a clean clone of the repository.
 9. For the following crates, cd into the directory, and do 'cargo
    publish':
       - buffered-reader
       - openpgp
       - sqv
10. In case of errors, correct them, and go back to 6.
11. Push the branch to master, push the tag.
12. Regenerate docs.sequoia-pgp.org.
