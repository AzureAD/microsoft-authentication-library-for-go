---
name: Bug report
about: Please do NOT file bugs without filling in this form.
title: '[Bug] '
labels: ''
assignees: ''

---

**Which version of MSAL Go are you using?**
Note that to get help, you need to run the latest version. 
<!-- E.g. Microsoft Authentication Library for Go 1.0.0-preview -->

**Where is the issue?**
* Public client
    * [ ] Device code flow
    * [ ] Username/Password (ROPC grant)
    * [ ] Authorization code flow 
* Confidential client
    * [ ] Authorization code flow 
    * [ ] Client credentials:
        * [ ] client secret
        * [ ] client certificate
* Token cache serialization
     * [ ] In-memory cache
* Other (please describe)

**Is this a new or an existing app?**
<!-- Ex:
a. The app is in production and I have upgraded to a new version of Microsoft Authentication Library for Go.
b. The app is in production and I haven't upgraded Microsoft Authentication Library for Go, but started seeing this issue.
c. This is a new app or an experiment.
-->

**What version of Go are you using (`go version`)?**

<pre>
$ go version
</pre>

**What operating system and processor architecture are you using (`go env`)?**

<details><summary><code>go env</code> Output</summary><br><pre>
$ go env

</pre></details>

**Repro**

<code>var your = (code) => here;</code>

**Expected behavior**
A clear and concise description of what you expected to happen (or code).

**Actual behavior**
A clear and concise description of what happens, e.g. an exception is thrown, UI freezes.

**Possible solution**
<!--- Only if you have suggestions on a fix for the bug. -->

**Additional context / logs / screenshots**
Add any other context about the problem here, such as logs and screenshots.
