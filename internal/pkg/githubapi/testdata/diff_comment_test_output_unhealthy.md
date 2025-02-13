

Diff of ArgoCD applications:




<img src="https://argo-cd.readthedocs.io/en/stable/assets/favicon.png" width="20"/> **[temp-ssllab-test-plg-aws-eu-central1-v1](https://argocd-lab.example.com/applications/temp-ssllab-test-plg-aws-eu-central1-v1)** @ `clusters/playground/aws/eu-central-1/v1/special-delivery/ssllab-test/ssllab-test`
> [!CAUTION]  
> The ArgoCD app health status is currently Unhealthy





<details><summary>ArgoCD Diff(Click to expand):</summary>

```diff

/Service/ssllabs-exporter:
  (*unstructured.Unstructured)(
- 	nil,
+ 	&{
+ 		Object: map[string]any{
+ 			"apiVersion": string("v1"),
+ 			"kind":       string("Service"),
+ 			"metadata":   map[string]any{"labels": map[string]any{...}, "name": string("ssllabs-exporter")},
+ 			"spec": map[string]any{
+ 				"ports":    []any{...},
+ 				"selector": map[string]any{...},
+ 				"type":     string("ClusterIP"),
+ 			},
+ 		},
+ 	},
  )

/Deployment/ssllabs-exporter:
  (*unstructured.Unstructured)(
- 	nil,
+ 	&{
+ 		Object: map[string]any{
+ 			"apiVersion": string("apps/v1"),
+ 			"kind":       string("Deployment"),
+ 			"metadata":   map[string]any{"labels": map[string]any{...}, "name": string("ssllabs-exporter")},
+ 			"spec": map[string]any{
+ 				"replicas": int64(2),
+ 				"selector": map[string]any{...},
+ 				"template": map[string]any{...},
+ 			},
+ 		},
+ 	},
  )

```

</details>