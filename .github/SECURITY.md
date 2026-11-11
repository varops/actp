# Security policy

actp runs coding agents for remote clients, so security problems matter a lot here. Thank you for reporting them privately.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Only the maintainers see the report.

Please include:

- what an attacker can do, and what they need first (a token, network access, a local account …);
- the steps to reproduce it, and the actp version (`actp version`);
- whether it involves the server, the bridge, the dashboard or the tunnel.

We answer within 5 working days, and keep you updated until it is fixed. We credit reporters in the release notes, unless you prefer not to be named.

## Supported versions

Security fixes go into the latest release. Please upgrade before reporting.

## What counts

Examples of what we want to hear about:

- using actp without a valid token, or using an agent, folder or link a token is not allowed to use;
- leaving the allowed workspace folders through actp itself (for example a crafted `cwd`);
- reading or taking over another client's link or session;
- getting a token, a link id or spool data that you should not see;
- driving the local dashboard from another website or another user on the machine.

Out of scope: what an agent does with the rights it was given. A client token is meant to let its holder make the agents do what the server's user can do (see the README, "Security").
