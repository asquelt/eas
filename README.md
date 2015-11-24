# eas
Enterprise Audit Shell enables organizations to centrally control and audit UNIX shell access. Audit logs are recorded and archived detailing shell input and output, which can be played back and reviewed.

Can be used as login shell (where both ssh, sudo and serial/console logins will be recorded).

Originally by Douglas Richard Hanks, Jr. &lt;dhanks@gmail.com>, based on sudosh.

## Key features

* registers sessions interactively, as you type (editors, arrows, history, deletions - everything is recorded)
* registers noninteractive sessions (ie. scp/rsync commands, remote deploys with ansible, capistrano, etc)
* saves sessions to central log location in real-time (allows snooping, including optional logging of user input)
* saves sessions metadata to (searchable) sqlite database
* utilises PKI for mutual authentication and transmission privacy
* allows for fallback servers (ie. use server on localhost as last resort)
* allows for connect hooks validating policy (ie. off-hours logins) and remotely disconnecting violators

## TODO

* migrate to (asciinema)[https://asciinema.org/] file format
* rewrite in golang
* allow other database outputs (ie. mysql)

## License

LGPL
