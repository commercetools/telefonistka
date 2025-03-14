```diff
# apiVersion: commercetools.io/v1alpha1
# kind: Bar
# name: example-baz-bar
@@ rbacBindings.security-audit-viewer-vault.subjects @@
! - one list entry removed:
- - name: "vault:some-team@domain.tld"
-   kind: Group
! + one list entry added:
+   - name: "vault:some-team-name@domain.tld"
+     kind: Group

@@ spec.replicas @@
! ± value change
- 63
+ 42

```
