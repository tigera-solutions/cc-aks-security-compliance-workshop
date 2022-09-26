# Configure your cluster and install demo applications

**Goal:** Configure Calico parameters for a quicker visualization of the changes done during the workshop, and install and configure demo applications.

## Step 1 - Configure Calico paramenters

1. Configure log aggregation and flush intervals in your cluster, we will use 15s instead of default value 300s for lab testing only.   

    ```bash
    kubectl patch felixconfiguration default -p '{"spec":{"flowLogsFlushInterval":"15s"}}'
    kubectl patch felixconfiguration default -p '{"spec":{"dnsLogsFlushInterval":"15s"}}'
    kubectl patch felixconfiguration default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
    kubectl patch felixconfiguration default -p '{"spec":{"flowLogsFileAggregationKindForDenied":0}}'
    kubectl patch felixconfiguration default -p '{"spec":{"dnsLogsFileAggregationKind":0}}'
    ```

2. Configure Felix to collect TCP stats - this uses eBPF TC program and requires miniumum Kernel version of v5.3.0/v4.18.0-193. Further [documentation](https://docs.tigera.io/visibility/elastic/flow/tcpstats).


    ```bash
    kubectl patch felixconfiguration default -p '{"spec":{"flowLogsCollectTcpStats":true}}'
    ```

## Step 2 - Create policy tier and essential policies

1. Deploy policy tiers.

   We are going to deploy sample tiered policies in the cluster some .

   You can copy and past the command below:

   ```yaml
   kubectl apply -f - <<-EOF
   apiVersion: projectcalico.org/v3
   kind: Tier
   metadata:
     name: security
   spec:
     order: 500
   ---
   apiVersion: projectcalico.org/v3
   kind: Tier
   metadata:
     name: platform
   spec:
     order: 700
   EOF
   ```

   This will add tiers `security`, and `platform` to the Calico cluster.
    

2. Deploy base policy.

   Deploy the following base policy for allowing DNS access to all endpoints.

   ```yaml
   kubectl apply -f - <<-EOF
   apiVersion: projectcalico.org/v3
   kind: GlobalNetworkPolicy
   metadata:
     name: platform.allow-kube-dns
   spec:
     tier: platform
     order: 200
     selector: all()
     types:
     - Egress    
     egress:
       - action: Allow
         protocol: UDP
         source: {}
         destination:
           selector: k8s-app == "kube-dns"
           ports:
           - '53'
       - action: Pass
         source: {}
         destination: {}
   EOF
   ```

## STEP 3 - Install the demo applications

1. Deploy demo applications.

   Deploy the dev app stack

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/regismartins/cc-aks-security-compliance-workshop/main/manifests/dev-app-manifest.yaml
   ```
   
   Deploy the Online Boutique app stack

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/regismartins/cc-aks-security-compliance-workshop/main/manifests/kubernetes-manifests.yaml
   ```

## STEP 4 - Create the Global Reports and the Global Alerts

1. Deploy compliance reports which schedule as cronjob in every 15 min for cluster report and a cis benchmark report.

    >The compliance reports will be needed later in this workshop, this is why to use such aggressive cronjob. You can change the schedule at your discretion by editing it for your cluster.

    Deploy the global reports.

    ```yaml
    kubectl apply -f - <<-EOF
    apiVersion: projectcalico.org/v3
    kind: GlobalReport
    metadata:
      name: cis-results
      labels:
        deployment: production
    spec:
      reportType: cis-benchmark
      schedule: '*/15 * * * *'
      cis:
        highThreshold: 100
        medThreshold: 50
        includeUnscoredTests: true
        numFailedTests: 5
    ---
    apiVersion: projectcalico.org/v3
    kind: GlobalReport
    metadata:
      name: cluster-inventory
    spec:
      reportType: inventory
      schedule: '*/15 * * * *'
    ---
    apiVersion: projectcalico.org/v3
    kind: GlobalReport
    metadata:
      name: cluster-network-access
    spec:
      reportType: network-access
      schedule: '*/15 * * * *' 
    ---
    apiVersion: projectcalico.org/v3
    kind: GlobalReport
    metadata:
      name: cluster-policy-audit
    spec:
      reportType: policy-audit
      schedule: '*/15 * * * *'
    EOF
    ```

2. Deploy some global alerts.

   >This alerts will be explored later in the workshop.

   a. Unsanctioned DNS endpoint global alert

   ```yaml
   kubectl apply -f - <<-EOF
   apiVersion: projectcalico.org/v3
   kind: GlobalAlert
   metadata:
     name: dns.unsanctioned.access
   spec:
     description: "Pod attempted to access google.com domain"
     summary: "[dns] pod ${client_namespace}/${client_name_aggr} attempted to access '${qname}'"
     severity: 100
     dataSet: dns
     period: 1m
     lookback: 1m
     query: '(qname = "www.google.com" OR qname = "google.com")'
     aggregateBy: [client_namespace, client_name_aggr, qname]
     metric: count
     condition: gt
     threshold: 0
   EOF
   ```

   b. Lateral movement global alert

   ```yaml
   kubectl apply -f - <<-EOF
   apiVersion: projectcalico.org/v3
   kind: GlobalAlert
   metadata:
     name: network.lateral.access
   spec:
     description: "Alerts when pods with a specific label (security=strict) accessed by other workloads from other namespaces"
     summary: "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} has accessed ${dest_namespace}/${dest_name_aggr} with label security=strict"
     severity: 100
     period: 1m
     lookback: 1m
     dataSet: flows
     query: '("dest_labels.labels"="security=strict" AND "dest_namespace"="dev") AND "source_namespace"!="dev" AND "proto"="tcp" AND (("action"="allow" AND ("reporter"="dst" OR    "reporter"="src")) OR ("action"="deny" AND "reporter"="src"))'
     aggregateBy: [source_namespace, source_name_aggr, dest_namespace, dest_name_aggr]
     field: num_flows
     metric: sum
     condition: gt
     threshold: 0
   EOF
   ```

   c. HTTP Connections global Alerts

   ```yaml
   kubectl apply -f - <<-EOF
   apiVersion: projectcalico.org/v3
   kind: GlobalAlert
   metadata:
     name: http.connections
   spec:
     description: "HTTP connections to a target namespace"
     summary: "HTTP connections from ${source_namespace}/${source_name_aggr} to default/${dest_name_aggr}"
     severity: 50
     dataSet: flows 
     query: dest_namespace="default" AND dest_port=80
     aggregateBy: 
       - source_namespace
       - dest_name_aggr
       - source_name_aggr
     field: count
     metric: sum
     condition: gte
     threshold: 1
     EOF
     ```
      

3. Confirm the global compliance report and global alert are running.
    
   ```bash
   kubectl get globalreport
   kubectl get globalalert
   ``` 

   The output looks like as below:

   ```bash
   NAME                      CREATED AT 
   cis-results               2022-09-01T15:42:33Z
   cluster-inventory         2022-09-01T15:42:33Z
   cluster-network-access    2022-09-01T15:42:33Z
   cluster-policy-audit      2022-09-01T15:42:33Z
   
   NAME                      CREATED AT
   dns.unsanctioned.access   2022-09-01T15:42:40Z
   network.lateral.access    2022-09-01T15:42:40Z
   policy.globalnetworkset   2022-09-01T15:42:39Z
   ```

--- 
[:leftwards_arrow_with_hook: Back to Main](/README.md)