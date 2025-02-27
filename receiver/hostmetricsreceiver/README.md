# Host Metrics Receiver

| Status                   |                   |
| ------------------------ | ----------------- |
| Stability                | [beta]            |
| Supported pipeline types | metrics           |
| Distributions            | [core], [contrib] |

The Host Metrics receiver generates metrics about the host system scraped
from various sources. This is intended to be used when the collector is
deployed as an agent.

## Getting Started

The collection interval and the categories of metrics to be scraped can be
configured:

```yaml
hostmetrics:
  collection_interval: <duration> # default = 1m
  scrapers:
    <scraper1>:
    <scraper2>:
    ...
```

The available scrapers are:

| Scraper      | Supported OSs                | Description                                            |
| ------------ | ---------------------------- | ------------------------------------------------------ |
| [cpu]        | All except Mac<sup>[1]</sup> | CPU utilization metrics                                |
| [disk]       | All except Mac<sup>[1]</sup> | Disk I/O metrics                                       |
| [load]       | All                          | CPU load metrics                                       |
| [filesystem] | All                          | File System utilization metrics                        |
| [memory]     | All                          | Memory utilization metrics                             |
| [network]    | All                          | Network interface I/O metrics & TCP connection metrics |
| [paging]     | All                          | Paging/Swap space utilization and I/O metrics          |
| [processes]  | Linux                        | Process count metrics                                  |
| [process]    | Linux & Windows              | Per process CPU, Memory, and Disk I/O metrics          |

[cpu]: ./internal/scraper/cpuscraper/documentation.md
[disk]: ./internal/scraper/diskscraper/documentation.md
[filesystem]: ./internal/scraper/filesystemscraper/documentation.md
[load]: ./internal/scraper/loadscraper/documentation.md
[memory]: ./internal/scraper/memoryscraper/documentation.md
[network]: ./internal/scraper/networkscraper/documentation.md
[paging]: ./internal/scraper/pagingscraper/documentation.md
[processes]: ./internal/scraper/processesscraper/documentation.md
[process]: ./internal/scraper/processscraper/documentation.md

### Notes

<sup>[1]</sup> Not supported on Mac when compiled without cgo which is the default.

Several scrapers support additional configuration:

### Disk

```yaml
disk:
  <include|exclude>:
    devices: [ <device name>, ... ]
    match_type: <strict|regexp>
```

### File System

```yaml
filesystem:
  <include_devices|exclude_devices>:
    devices: [ <device name>, ... ]
    match_type: <strict|regexp>
  <include_fs_types|exclude_fs_types>:
    fs_types: [ <filesystem type>, ... ]
    match_type: <strict|regexp>
  <include_mount_points|exclude_mount_points>:
    mount_points: [ <mount point>, ... ]
    match_type: <strict|regexp>
```

### Load

`cpu_average` specifies whether to divide the average load by the reported number of logical CPUs (default: `false`).

```yaml
load:
  cpu_average: <false|true>
```

### Network

```yaml
network:
  <include|exclude>:
    interfaces: [ <interface name>, ... ]
    match_type: <strict|regexp>
```

### Process

```yaml
process:
  <include|exclude>:
    names: [ <process name>, ... ]
    match_type: <strict|regexp>
  mute_process_name_error: <true|false>
  scrape_process_delay: <time>
```

## Advanced Configuration

### Filtering

If you are only interested in a subset of metrics from a particular source,
it is recommended you use this receiver with the
[Filter Processor](../../processor/filterprocessor).

### Different Frequencies

If you would like to scrape some metrics at a different frequency than others,
you can configure multiple `hostmetrics` receivers with different
`collection_interval` values. For example:

```yaml
receivers:
  hostmetrics:
    collection_interval: 30s
    scrapers:
      cpu:
      memory:

  hostmetrics/disk:
    collection_interval: 1m
    scrapers:
      disk:
      filesystem:

service:
  pipelines:
    metrics:
      receivers: [hostmetrics, hostmetrics/disk]
```

### Feature gate configurations

#### Transition from metrics with "direction" attribute

The proposal to change metrics from being reported with a `direction` attribute has been reverted in the specification. As a result, the
following feature gates will be removed in v0.62.0:

- **receiver.hostmetricsreceiver.emitMetricsWithoutDirectionAttribute**
- **receiver.hostmetricsreceiver.emitMetricsWithDirectionAttribute**

For additional information, see https://github.com/open-telemetry/opentelemetry-specification/issues/2726.

##### More information:

- https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/11815
- https://github.com/open-telemetry/opentelemetry-specification/pull/2617

[beta]: https://github.com/open-telemetry/opentelemetry-collector#beta
[contrib]: https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-contrib
[core]: https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol

