---
name: Bug report
about: Please do NOT file bugs without filling in this form.
title: '[Bug] '
labels: ''
assignees: ''

---

**Which version of Microsoft Go are you using?**
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

**Repro**

```csharp
var your = (code) => here;
```

**Expected behavior**
A clear and concise description of what you expected to happen (or code).

**Actual behavior**
A clear and concise description of what happens, e.g. an exception is thrown, UI freezes.

**Possible solution**
<!--- Only if you have suggestions on a fix for the bug. -->

**Additional context / logs / screenshots**
Add any other context about the problem here, such as logs and screenshots.
