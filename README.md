# Microsoft Azure: Hands-on AKS workshop
## Configuration Security and Compliance

In this AKS-focused workshop, you will work with Microsoft Azure and Calico Cloud to learn how to design and deploy best practices to secure your Kubernetes environment and achieve compliance with regulatory frameworks such as PCI, SOC2 and GDPR. This 90-minute hands-on lab will guide you from building an AKS cluster, creating a Calico Cloud trial account and registering your AKS cluster to Calico Cloud for configuring and securing it for compliance. A sample app environment is designed to help implement:

- Configuration security including Kubernetes Security Posture Management (KSPM) 
- Security policies for compliance
- Compliance, evidence, and audit reporting

You will come away from this workshop with an understanding of how others in your industry are securing and observing cloud-native applications in Microsoft Azure, along with best practices that you can implement in your organization.

---

## Create a cluster an connect it to Calico Cloud.

If you don't have an AKS cluster created for this workshop, we recommend you create one. You can follow the steps here to create a Calico Cloud compatible AKS cluster to follow along with this workshop.

   - [Azure AKS Cluster Creation - Azure CNI for Calico Cloud](./aks-azurecni.md)
   
   > **Connect your cluster to** [Calico Cloud](https://calicocloud.io)

---

## How Calico supports PCI compliance requirements

Tigera’s solutions, Calico Cloud and Calico Enterprise, enable north-south controls such as egress access, east-west controls such as microsegmentation, and enterprise security controls, policy enforcement, and compliance reporting across all Kubernetes distributions in both hybrid and multi-cloud environments. Calico provides the following features to help achieve PCI compliance.


## Access controls

Calico provides methods to enable fine-grained access controls between your microservices and external databases, cloud services, APIs, and other applications that are protected behind a firewall. You can enforce controls from within the cluster using DNS egress policies, from a firewall outside the cluster using the egress gateway. Controls are applied on a fine-grained, per-pod basis.


| PCI Control # | Requirements| How Calico meets this requirements |
| --- | --- | --- |
|1.1, 1.1.4, 1.1.6, 1.2.1, 1.2.2, 1.2.3 | Install and maintain a firewall configuration to protect cardholder data | • Identify everything covered by PCI requirements with a well-defined label (e.g. PCI=true)<br>• Block all traffic between PCI and non-PCI workloads<br>• Whitelist all traffic within PCI workloads |

--- 

Scenario of microsegmentation using label PCI = true on a namespace

---


| PCI Control # | Requirements| How Calico meets this requirements |
| ------------- | --- | --- |
|1.1.2, 1.1.3| Current network diagram that identifies all connections between the CDE and other networks and systems | • Stay current with the network diagram for in-scope workloads in Kubernetes environments using Calico’s Dynamic Service Graph and flow visualizer |

---

Demo - Service Graph and flow visualizer

---




## Microsegmentation

Calico eliminates the risks associated with lateral movement in the cluster to prevent access to sensitive data and other assets. Calico provides a unified, cloud-native segmentation model and single policy framework that works seamlessly across multiple application and workload environments. It enables faster response to security threats
with a cloud-native architecture that can dynamically enforce security policy changes across cloud environments in milliseconds in response to an attack.


## IDS/IPS

Calico pinpoints the source of malicious activity, uses machine learning to identify anomalies, creates a security moat
around critical workloads, deploys honeypods to capture zero-day attacks, and automatically quarantines potentially
malicious workloads to thwart an attack. It monitors inbound and outbound traffic (north-south) and east-west traffic
that is traversing the cluster environment. Calico provides threat feed integration and custom alerts, and can be
configured to trigger automatic remediation.



## Policy lifecycle management


With Calico, teams can create, preview, and deploy security policies based on the characteristics and metadata
of a workload. These policies can provide an automated and scalable way to manage and isolate workloads for
security and compliance, in adherence with PCI compliance requirements. You can automate a validation step that
ensures your security policy works properly before being committed. Calico can deploy your policies in a “staged”
mode that will display which traffic is being allowed or denied before the policy rule is enforced. The policy can then
be committed if it is operating properly. This step avoids any potential problems caused by incorrect, incomplete, or
conflicting security policy definitions.


## Encryption

Calico’s data-in-transit encryption provides category-leading performance and lower CPU utilization than legacy
approaches based on IPsec and OpenVPN tunneling protocols. No matter where a threat originates, data encrypted
by Calico is unreadable to anyone except the legitimate keyholder, thus protecting sensitive data should a perimeter
breach occur. It enables compliance with corporate and regulatory data protection requirements, such as PCI, that
specify the use of encryption. Calico’s encryption is 6X faster than any other solution on the market.



## Compliance Reports

Continuous compliance means employing a continual audit that shows what traffic was allowed in your infrastructure,
what traffic was denied and why, and logs of who was trying to change what and whether those changes went into
effect. Continuous compliance gives teams the ability to pinpoint any point in time and say with reasonable certainty
whether the organization was in compliance—and provide documentation to prove it. Calico’s compliance reports
visually describe the security controls in place in an easy-to-understand policy view. Calico also shows all workloads
that are in-scope and out-of-scope with your policy.


## Demo Preparation Config

1. Accelerate the log export.

   ```bash
   kubectl patch felixconfiguration default -p '{"spec":{"flowLogsFlushInterval":"15s"}}'
   kubectl patch felixconfiguration default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
   kubectl patch felixconfiguration default -p '{"spec":{"flowLogsFileAggregationKindForDenied":0}}'
   kubectl patch felixconfiguration default -p '{"spec":{"dnsLogsFileEnabled":true}}'
   kubectl patch felixconfiguration default -p '{"spec":{"dnsLogsFileAggregationKind":0}}'
   kubectl patch felixconfiguration default -p '{"spec":{"dnsLogsFlushInterval":"15s"}}'
   kubectl patch felixconfiguration default -p '{"spec":{"l7LogsFlushInterval":"15s"}}'
   ```












2. If **WireGuard** needs to be configured, do it now.
   
   >  :warning: **IF YOU ENABLE WIREGUARD FOR AN AKS CLUSTER, L7 LOGGING WILL NEVER WORK**

   [Reference documentation](https://docs.calicocloud.io/compliance/encrypt-cluster-pod-traffic)

      >Only Supported on:
      >
      >The following platforms using only IPv4:
      >    - Kubernetes, on-premises
      >    - EKS using Calico CNI
      >    - EKS using AWS CNI
      >    - AKS using Azure CNI
      >
      >All platforms listed above will encrypt pod-to-pod traffic. Additionally, when using AKS or EKS, host-to-host traffic will also be encrypted, including host-networked pods.

   <details>
      <summary> EKS </summary>
       
      1. Install WireGuard on each node:
   
         ```bash
         sudo yum install kernel-devel-`uname -r` -y
         sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
         sudo curl -o /etc/yum.repos.d/jdoss-wireguard-epel-7.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
         sudo yum install wireguard-dkms wireguard-tools -y
         ```
   
      2. Enable WireGuard for the cluster
   
         ```bash
         kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
         ```
   
      3. Verify if enabled
   
         ```bash
         NODENAME=$(kubectl get nodes -o=jsonpath='{.items[0].metadata.name}')
         kubectl get node $NODENAME -o yaml | grep -B2 -A5 annotation
         ```
   
      4. Enable stats collection
   
         ```bash
         kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"nodeMetricsPort":9091}}'
         ```
   
      5. Apply Service, ServiceMonitor, NetworkPolicy manifests:
   
         ```bash
         kubectl apply -f ./demo-prep/wireguard-stats.yaml
         ```
   
      6. Disable WireGuard for the cluster 
   
         ```bash
         kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
         ```
   </details>

   <details>
      <summary> AKS </summary>
       
      1. Install WireGuard is already installed on Ubuntu nodes.
   
      2. Enable WireGuard for the cluster
   
         ```bash
         kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
         ```
   
      3. Verify if enabled
   
         ```bash
         NODENAME=$(kubectl get nodes -o=jsonpath='{.items[0].metadata.name}')
         kubectl get node $NODENAME -o yaml | grep -B2 -A5 annotation
         ```
   
      4. Enable stats collection
   
         ```bash
         kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"nodeMetricsPort":9091}}'
         ```
   
      5. Apply Service, ServiceMonitor, NetworkPolicy manifests:
   
         ```bash
         kubectl apply -f ./demo-prep/wireguard-stats.yaml
         ```
   
      6. Disable WireGuard for the cluster
   
         ```bash
         kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
         ```
   </details>

3. **Demo Preparation Manifests**

   This manifest will create:
   
   - Tiers "security" and "platform"
   - DNS GlobalNetworkPolicy
   - Global Reports
   - Global Alerts

   ```bash 
   kubectl apply -f ./demo-prep/demo-manifest.yaml
   ```
   
4. **Install the applications**

   Online Boutique 0.3.9

   ```bash 
   kubectl apply -f ./demo-prep/kubernetes-manifests.yaml
   ```

   Dev App Stack

   ```bash 
   kubectl apply -f ./demo-prep/dev-app-manifest.yaml
   ```

   Install curl on the loadgen, just in case :)

   ```bash 
   kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -c main -- sh -c 'apt-get update && apt install curl -y'
   ```

5. **L7 Logging**

   1. Policy Sync Path
   
      ```bash 
      kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"policySyncPathPrefix":"/var/run/nodeagent"}}'
      ```
   
   2. Application Layer
   
      ```yaml 
      kubectl apply -f - <<-EOF
      apiVersion: operator.tigera.io/v1
      kind: ApplicationLayer
      metadata:
        name: tigera-secure
      spec:
        logCollection:
          collectLogs: Enabled
          logIntervalSeconds: 5
          logRequestsPerInterval: -1
      EOF
      ```
   
   3. Annotate the services
   
      ```bash 
      kubectl annotate svc frontend projectcalico.org/l7-logging=true
      kubectl annotate svc frontend-external projectcalico.org/l7-logging=true
      ```
  

6. **Honeypods**


   1. Create dedicated namespace and RBAC for honeypods
   
      ```bash
      kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/common.yaml
      ```
   
   2. Add tigera pull secret to the namespace. We clone the existing secret from the calico-system NameSpace
   
      ```bash
      kubectl get secret tigera-pull-secret --namespace=calico-system -o yaml | \
      grep -v '^[[:space:]]*namespace:[[:space:]]*calico-system' | \
      kubectl apply --namespace=tigera-internal -f -
      ```
   
   3. Expose IPs and service ports
   
      - Expose pod IP to test IP enumeration and port scan use case
      
        ```bash
        kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/ip-enum.yaml
        ```
      
      - Expose nginx service that can be reached via ClusterIP or DNS. Create two service, one unreachable, one debug
      
        ```bash
        kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/expose-svc.yaml 
        ```
      
      - Expose MySQL service
        
        ```bash
        kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/vuln-svc.yaml 
        ```
   
   4. Attacking the Honeypods
   
      - HoneyPod enumeration
      
        ```bash
        POD_IP=$(kubectl -n tigera-internal get po --selector app=tigera-internal-app -o jsonpath='{.items[0].status.podIP}')
        kubectl -n dev exec netshoot -- ping -c5 $POD_IP
        ```
      - HoneyPod nginx service
      
        ```bash
        SVC_URL=$(kubectl -n tigera-internal get svc -l app=tigera-dashboard-internal-debug -ojsonpath='{.items[0].metadata.name}')
        SVC_PORT=$(kubectl -n tigera-internal get svc -l app=tigera-dashboard-internal-debug -ojsonpath='{.items[0].spec.ports[0].port}')
        kubectl -n dev exec netshoot -- curl -m3 -skI $SVC_URL.tigera-internal:$SVC_PORT | grep -i http
        ```
      
      - HoneyPod MySQL service
      
        ```bash
        SVC_URL=$(kubectl -n tigera-internal get svc -l app=tigera-internal-backend -ojsonpath='{.items[0].metadata.name}')
        SVC_PORT=$(kubectl -n tigera-internal get svc -l app=tigera-internal-backend -ojsonpath='{.items[0].spec.ports[0].port}')
        kubectl -n dev exec netshoot -- nc -zv $SVC_URL.tigera-internal $SVC_PORT
        ```
   
7. **Deep Packet Inspection**

   1. Create the DPI and the Intrusion Detection for the dev/nginx service.

      ```yaml
      kubectl apply -f - <<-EOF
      apiVersion: projectcalico.org/v3
      kind: DeepPacketInspection
      metadata:
        name: dpi-nginx
        namespace: dev
      spec:
        selector: app == "nginx"
      ---
      apiVersion: operator.tigera.io/v1
      kind: IntrusionDetection
      metadata:
        name: tigera-secure
      spec:
        componentResources:
        - componentName: DeepPacketInspection
          resourceRequirements:
            limits:
              cpu: "1"
              memory: 1Gi
            requests:
              cpu: 100m
              memory: 100Mi
      EOF
      ```
   
   2. Attack the nginx service

      ```bash
      kubectl -n dev exec -t netshoot -- sh -c "curl -m2 http://nginx-svc/ -H 'User-Agent: Mozilla/4.0' -XPOST --data-raw 'regis=1234'"
      kubectl -n dev exec -t netshoot -- sh -c "curl -m2 http://nginx-svc/secid_canceltoken.cgi -H 'X-CMD: Test' -H 'X-KEY: Test' -XPOST"
      kubectl -n dev exec -t netshoot -- sh -c "curl -m2 http://nginx-svc/cmd.exe"
      kubectl -n dev exec -t netshoot -- sh -c "curl -m2 http://nginx-svc/NessusTest"
      ```

      [Check the Snort Id here!](https://www.snort.org/search)

8. **OFAC Sanctions List**

   1. Create the OFAC Threatfeed

      ```yaml
      kubectl apply -f - <<-EOF
      apiVersion: projectcalico.org/v3
      kind: GlobalThreatFeed
      metadata:
        name: ofac-sanctions
      spec:
        pull:
          http:
            url: http://tigera.rocks/ofac-sanctions-ipblocklist.txt 
        globalNetworkSet:
          labels:
            threatfeed: ofac
      EOF
      ```

   2. Create the deny rule to OFAC list

      ```yaml
      kubectl apply -f - <<-EOF
      apiVersion: projectcalico.org/v3
      kind: GlobalNetworkPolicy
      metadata:
        name: security.ofac-sanctions
      spec:
        tier: security
        order: 200
        selector: all()
        types:
        - Egress
        egress:
        - action: Deny
          destination:
            selector: threatfeed == "ofac"
        - action: Pass
      EOF
      ```

   3. Global Alert for OFAC List access attempt
   
      ```yaml
      kubectl apply -f - <<-EOF
      apiVersion: projectcalico.org/v3
      kind: GlobalAlert
      metadata:
        name: security.ofac-sanctions
      spec:
        description: "Alerts when pods try to access OFAC sanctioned sites"
        summary: "[flows] [ofac-sanction] ${source_namespace}/${source_name_aggr} has tried to access ${dest_ip}"
        severity: 100
        period: 1m
        lookback: 1m
        dataSet: flows
        query: dest_name_aggr="threatfeed.ofac-sanctions"
        aggregateBy: [source_namespace, source_name_aggr, dest_name_aggr, dest_ip]
        field: num_flows
        metric: sum
        condition: gt
        threshold: 0
      EOF
      ```

   **Done! Your cluster is ready to start with the demo!**
   
---

## Choose your Demo script
  
   - [Calico Cloud](./cc-demo.md)
   - [Calico Enterprise](./ce-demo.md)

