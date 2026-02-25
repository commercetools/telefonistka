Diff of ArgoCD applications:

<img src="https://argo-cd.readthedocs.io/en/stable/assets/favicon.png" width="20"/> **[my-service-prd-aws-eu-central1-v1](https://argocd.example.com/applications/my-service-prd-aws-eu-central1-v1)** @ `clusters/production/aws/eu-central-1/v1/team/my-service`
> [!WARNING]  
> This component is being **removed**. All resources below will be deleted from the cluster.

<details><summary>ArgoCD Diff(Click to expand):</summary>

```diff

production/Deployment/my-service:
- replicas: 2
- image: my-service:v1.2.3
production/Service/my-service:
- port: 8080
- targetPort: 8080


```

</details>
