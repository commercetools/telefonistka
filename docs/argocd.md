# ArgoCD-specific features

While Telefonistka was initially written to be agnostic of the IaC stack some ArgoCD specific features where added recently, this document describes them.

## Commenting diff on PRs

In most cases users directly manipulate Kubernetes manifests in their DRY form (Helm chart/value files or Kustomize configuration), causing a change to have unexpected results in the rendered manifests. Additionally, the state of the in-cluster objects is not always known in advance which prevents the users from knowing the exact change that will happen in the cluster after merging a PR.

By posting the differences between the cluster objects and the manifests rendered from the PR branch the PR author **and reviewer** can have a better understanding of the effects of a PR merge.

In cases where the rendered diff output goes over the maximum GitHub comment size limit, Telefonistka will try to split each ArgoCD application diff into a separate comment.

If a single application diff is still bigger that the max comment size, Telefonistka will only list the changed objects instead of showing the entire changed content.

If the list of changed objects pushed the comment size beyond the max size Telefonistka will explode, maybe, probably.

Telefonistka can even "diff" new applications, ones that do not yet have an ArgoCD application object (e.g. the application has not been merged to main yet). But this feature is currently implemented in a somewhat opinionated way and only support applications created by `ApplicationSets` with a Git Directory Generator or a Custom Plugin Generator that accept a `Path` parameter.

This behavior is gated behind the `argocd.createTempAppObjectFromNewApps` [configuration key](installation.md).

Example:

<!-- markdownlint-disable MD033 -->
<img width="960" alt="image" src="https://github.com/user-attachments/assets/d821a2b2-0b83-44f3-9875-8dfa4909d6e9" />
<!-- markdownlint-enable MD033 -->

## Warn user on changes to unhealthy/OutOfSync apps

Telefonistka checks the state of the ArgoCD application and adds warning for this states:

1) App is "Unhealthy"

2) App is "OutOfSync"

3) `auto-sync` is not enabled

Example:

<!-- markdownlint-disable MD033 -->
<img width="923" alt="image" src="https://github.com/user-attachments/assets/4b1ec561-3772-4179-aa28-71e71b826eae" />
<!-- markdownlint-enable MD033 -->

## Selectively allow temporary syncing of applications from non main branch

While displaying a diff in the PR can catch most templating issues, sometime testing a change in a non production environment is needed. If you want to test the configuration before merging the PR you can selectively allow a PR that manipulate files in specific folders to include the `Set ArgoCD apps Target Revision to <Pull Request Branch>` checkbox.

![image](https://github.com/user-attachments/assets/c2b5c56b-865f-411d-9b72-e8cc0001151f)

If the checkbox is marked Telefonistka will set the ArgoCD application object `/spec/source/targetRevision` key to the PR branch. If you have `auto-sync` enabled ArgoCD will sync the workload object from the branch.

On PR merge, Telefonistka will revert `/spec/source/targetRevision` back to the main branch.

> [!Note]
> As of the time of this writing, Telefonistka will **not**  revert  `/spec/source/targetRevision` to the main branch when you uncheck the checkbox, only on PR merge.

This feature is gated with the `argocd.allowSyncfromBranchPathRegex` configuration key.

This example configuration will enable synchronising from a non-main branch feature for PRs that only manipulate files under the `env/staging/` folder:

```yaml
argocd:
  allowSyncfromBranchPathRegex: '^env/staging/.*$'
```

> [!NOTE]
> The `ApplicationSet` controller might need to be configured to ignore changes to this specific key, like so:
>
> ```yaml
> spec:
>  ignoreApplicationDifferences:
>    - jsonPointers:
>        - /spec/source/targetRevision
> ```

## AutoMerge "no diff" Promotion PRs

When Telefonistka promote a change it copies the component folder in its entirety. This can lead to situations where a promotion PR is opened but does not affect a promotion target, either because the nature of the change (whitespace/doc) or because the resulting rendered manifests does not change **for the target clusters** (like when you change a target-specific Helm value/Kustomize configuration).

In those cases Telefonistka can auto-merge the promotion PR, saving the effort of merging the PR and preventing future changes from getting an environment drift warning (TODO link).

 This behavior is gated behind the `argocd.autoMergeNoDiffPRs` [configuration key](installation.md).

## Proxy github webhooks

While not strictly an "ArgoCD feature" Telefonistk ability to proxy webhooks can provide flexability in configuration and securing webhook to ArgoCD server and the AppplicationSet controlelr, see [here](webhook_multiplexing.md)
