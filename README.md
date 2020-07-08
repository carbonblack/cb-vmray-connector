# Carbon Black - VmRay Connector

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-vmray-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/vmray/connector.conf.example` file to
`/etc/cb/integrations/vmray/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

To start the service, run `service cb-vmray-connector start` as root. Any errors will be logged into `/var/log/cb/integrations/vmray/vmray.log`.

## Troubleshooting

If you suspect a problem, please first look at the vmray connector logs found here: `/var/log/cb/integrations/vmray/vmray.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-vmray-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/vmray/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-vmray-connector start`

## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
