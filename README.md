<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# Blip

> [!NOTE]
> Blip is in active development. The product and this documentation are not yet ready for serious use.

Blip provides a Kubernetes-native platform for running workloads in isolated virtual machines with durable, persistent workspaces. Run any command with fast startup, then resume it later or from another machine.

## Core concepts

- **Blip**: A single execution of a command in a virtual machine.
- **BlipState**: A durable workspace/filesystem that persists across executions. States can be created empty, imported from an OCI container image, or copied/forked from another state.
- **BlipPool**: The execution environment and VM profile for Blips.

## What you can do

- Run any command or process in a hardware-isolated VM with fast startup from a pool of warm VMs.
- Create and use durable workspaces that persist files, installed packages, and state across executions.
- Fork a workspace cheaply for parallel work, with each fork private and starting from the same files.
- Import container images as read-only base templates and copy them to create writable workspaces.
- Attach multiple durable data volumes (read-only or writable) to a running workload.
- Control Blips from `kubectl` via a `kubectl blip` plugin to run commands, gather results, logs, stdin, stop executions, mount volumes, and import container images.
- Record stdin, stdout, stderr, and exit status for each execution, readable while running and after the VM is gone, with timeouts, idle timeouts, and TTL-based cleanup.
- Use controlled network egress policies and in-guest access to the Kubernetes API as the Blip's own service account, through a pod-local Envoy sidecar that also proxies fixed HTTPS endpoints.

## Architecture

Blip runs on Kubernetes and uses a controller to manage pools, states, and executions. A per-node agent provides encrypted replicated storage and VM lifecycle management. Workloads run in Cloud Hypervisor VMs inside ordinary Pods. Each VM Pod's Envoy sidecar injects the Blip's pod-bound service-account token and proxies its fixed HTTPS endpoints. Users interact with Blip through the Kubernetes API and the CLI.

## Status

Blip is under active development. Product documentation and getting-started guides will be available soon.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
