# ArgoCD-specific feature

While Telefonistka was initially written to be agnostic of the IaC stack some ArgoCD specific features where added recently, this document describes them

## Commenting Diff on PRs

In most cases users directly manipulate Kubernetes manifests in their DRY form(Helm chart/value files or Kustomize configuration), causing a change to have unexpected results in the rendered manifests, additionally, the state of the in cluster objects in not always known in advance preventing the users from knowing the exact change that will happen in the cluster after merging a PR.

By posting the diffrences between the cluster objects and the manifests rendered from the PR branch the PR author **and reviewer** can have a better understanding of the PR merge actual affect.

In case the diff output pushes to comment size over the maximum GitHub comment size Telefonistka will try to split each ArgoCD application Diff to a separate comment.

If a single application diff is still bigger that the max comment size Telefonistka will only list the changed objects instead of showing the changed content.

If the list of changed objects pushed the comment size beyond the max size Telefonistka will explode, maybe, probably.

Telefonistka can even "diff" new applications, that don't yet have an ArgoCD application object. But this feature is currently implemented in a somewhat opinionated way and only support application created by ApplicationSets with Git Directory generators or Custom Plugin generator that accept a `Path` parameter.  This behavior is gated behind the `argocd.createTempAppObjectFromNewApps` [configuration key](installation.md).

TODO screenshot

## Warn user on changes to unhealthy/OutOfSync apps

Telefonistka also checks the state of ArgoCD application and adds warning for this states:

1) App is "Unhealthy"

2) App is "OutOfSync"

3) `auto-sync` is not enabled

TODO screenshot

## AutoMerge "no diff" Promotion PRs

When Telefonistka promote a change it copies the component older in its entirety, this can lead to situations where a promotion PR is opened but doesn't affect a promotion target, either because the nature of the change(whitespace/doc) or because the resulting rendered manifests doesn't change **for the target clusters** (like when you change a target-specific  Helm value/Kustomize configuration).

In those cases Telefonistka can Auto Merge the promotion PR, saving the effort of merging the PR and preventing future changes from getting environment drift warning(TODO link).

 This behavior is gated behind the `argocd.autoMergeNoDiffPRs` [configuration key](installation.md).

## Proxy github webhooks

While not strictly an "ArgoCD feature" Telefonistk ability to proxy webhooks can provide flexability in configuration and securing webhook to ArgoCD server and the AppplicationSet controlelr, see [here](webhook_multiplexing.md)
