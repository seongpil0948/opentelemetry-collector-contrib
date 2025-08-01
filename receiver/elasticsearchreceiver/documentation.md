[comment]: <> (Code generated by mdatagen. DO NOT EDIT.)

# elasticsearch

## Default Metrics

The following metrics are emitted by default. Each of them can be disabled by applying the following configuration:

```yaml
metrics:
  <metric_name>:
    enabled: false
```

### elasticsearch.breaker.memory.estimated

Estimated memory used for the operation.

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of circuit breaker. | Any Str | false |

### elasticsearch.breaker.memory.limit

Memory limit for the circuit breaker.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of circuit breaker. | Any Str | false |

### elasticsearch.breaker.tripped

Total number of times the circuit breaker has been triggered and prevented an out of memory error.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of circuit breaker. | Any Str | false |

### elasticsearch.cluster.data_nodes

The number of data nodes in the cluster.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {nodes} | Sum | Int | Cumulative | false |

### elasticsearch.cluster.health

The health status of the cluster.

Health status is based on the state of its primary and replica shards. Green indicates all shards are assigned. Yellow indicates that one or more replica shards are unassigned. Red indicates that one or more primary shards are unassigned, making some data unavailable.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {status} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| status | The health status of the cluster. | Str: ``green``, ``yellow``, ``red`` | false |

### elasticsearch.cluster.in_flight_fetch

The number of unfinished fetches.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {fetches} | Sum | Int | Cumulative | false |

### elasticsearch.cluster.nodes

The total number of nodes in the cluster.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {nodes} | Sum | Int | Cumulative | false |

### elasticsearch.cluster.pending_tasks

The number of cluster-level changes that have not yet been executed.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {tasks} | Sum | Int | Cumulative | false |

### elasticsearch.cluster.published_states.differences

Number of differences between published cluster states.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | State of the published differences | Str: ``incompatible``, ``compatible`` | false |

### elasticsearch.cluster.published_states.full

Number of published cluster states.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | false |

### elasticsearch.cluster.shards

The number of shards in the cluster.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {shards} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | The state of the shard. | Str: ``active``, ``active_primary``, ``relocating``, ``initializing``, ``unassigned``, ``unassigned_delayed`` | false |

### elasticsearch.cluster.state_queue

Number of cluster states in queue.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | State of the published differences | Str: ``pending``, ``committed`` | false |

### elasticsearch.cluster.state_update.count

The number of cluster state update attempts that changed the cluster state since the node started.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | State of cluster state update | Any Str | false |

### elasticsearch.cluster.state_update.time

The cumulative amount of time updating the cluster state since the node started.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| ms | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | State of cluster state update | Any Str | false |
| type | Type of cluster state update | Str: ``computation``, ``context_construction``, ``commit``, ``completion``, ``master_apply``, ``notification`` | false |

### elasticsearch.index.documents

The number of documents for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | The state of the document. | Str: ``active``, ``deleted`` | false |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.operations.completed

The number of operations completed for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operations} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| operation | The type of operation. | Str: ``index``, ``delete``, ``get``, ``query``, ``fetch``, ``scroll``, ``suggest``, ``merge``, ``refresh``, ``flush``, ``warmer`` | false |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.operations.merge.current

The number of currently active segment merges

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| {merges} | Gauge | Int |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.operations.time

Time spent on operations for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| ms | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| operation | The type of operation. | Str: ``index``, ``delete``, ``get``, ``query``, ``fetch``, ``scroll``, ``suggest``, ``merge``, ``refresh``, ``flush``, ``warmer`` | false |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.segments.count

Number of segments of an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {segments} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.shards.size

The size of the shards assigned to this index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.indexing_pressure.memory.limit

Configured memory limit, in bytes, for the indexing requests.

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

### elasticsearch.indexing_pressure.memory.total.primary_rejections

Cumulative number of indexing requests rejected in the primary stage.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

### elasticsearch.indexing_pressure.memory.total.replica_rejections

Number of indexing requests rejected in the replica stage.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

### elasticsearch.memory.indexing_pressure

Memory consumed, in bytes, by indexing requests in the specified stage.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| stage | Stage of the indexing pressure | Str: ``coordinating``, ``primary``, ``replica`` | false |

### elasticsearch.node.cache.count

Total count of query cache misses across all shards assigned to selected nodes.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {count} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| type | Type of query cache count | Str: ``hit``, ``miss`` | false |

### elasticsearch.node.cache.evictions

The number of evictions from the cache on a node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {evictions} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| cache_name | The name of cache. | Str: ``fielddata``, ``query`` | false |

### elasticsearch.node.cache.memory.usage

The size in bytes of the cache on a node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| cache_name | The name of cache. | Str: ``fielddata``, ``query`` | false |

### elasticsearch.node.cluster.connections

The number of open tcp connections for internal cluster communication.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {connections} | Sum | Int | Cumulative | false |

### elasticsearch.node.cluster.io

The number of bytes sent and received on the network for internal cluster communication.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| direction | The direction of network data. | Str: ``received``, ``sent`` | false |

### elasticsearch.node.disk.io.read

The total number of kilobytes read across all file stores for this node.

This metric is available only on Linux systems.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| KiBy | Sum | Int | Cumulative | false |

### elasticsearch.node.disk.io.write

The total number of kilobytes written across all file stores for this node.

This metric is available only on Linux systems.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| KiBy | Sum | Int | Cumulative | false |

### elasticsearch.node.documents

The number of documents on the node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | The state of the document. | Str: ``active``, ``deleted`` | false |

### elasticsearch.node.fs.disk.available

The amount of disk space available to the JVM across all file stores for this node. Depending on OS or process level restrictions, this might appear less than free. This is the actual amount of free disk space the Elasticsearch node can utilise.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.fs.disk.free

The amount of unallocated disk space across all file stores for this node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.fs.disk.total

The amount of disk space across all file stores for this node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.http.connections

The number of HTTP connections to the node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {connections} | Sum | Int | Cumulative | false |

### elasticsearch.node.ingest.documents

Total number of documents ingested during the lifetime of this node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | true |

### elasticsearch.node.ingest.documents.current

Total number of documents currently being ingested.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | false |

### elasticsearch.node.ingest.operations.failed

Total number of failed ingest operations during the lifetime of this node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operation} | Sum | Int | Cumulative | true |

### elasticsearch.node.open_files

The number of open file descriptors held by the node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {files} | Sum | Int | Cumulative | false |

### elasticsearch.node.operations.completed

The number of operations completed by a node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operations} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| operation | The type of operation. | Str: ``index``, ``delete``, ``get``, ``query``, ``fetch``, ``scroll``, ``suggest``, ``merge``, ``refresh``, ``flush``, ``warmer`` | false |

### elasticsearch.node.operations.time

Time spent on operations by a node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| ms | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| operation | The type of operation. | Str: ``index``, ``delete``, ``get``, ``query``, ``fetch``, ``scroll``, ``suggest``, ``merge``, ``refresh``, ``flush``, ``warmer`` | false |

### elasticsearch.node.pipeline.ingest.documents.current

Total number of documents currently being ingested by a pipeline.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | Name of the ingest pipeline. | Any Str | false |

### elasticsearch.node.pipeline.ingest.documents.preprocessed

Number of documents preprocessed by the ingest pipeline.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | Name of the ingest pipeline. | Any Str | false |

### elasticsearch.node.pipeline.ingest.operations.failed

Total number of failed operations for the ingest pipeline.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operation} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | Name of the ingest pipeline. | Any Str | false |

### elasticsearch.node.script.cache_evictions

Total number of times the script cache has evicted old data.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

### elasticsearch.node.script.compilation_limit_triggered

Total number of times the script compilation circuit breaker has limited inline script compilations.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

### elasticsearch.node.script.compilations

Total number of inline script compilations performed by the node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {compilations} | Sum | Int | Cumulative | false |

### elasticsearch.node.shards.data_set.size

Total data set size of all shards assigned to the node. This includes the size of shards not stored fully on the node, such as the cache for partially mounted indices.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.shards.reserved.size

A prediction of how much larger the shard stores on this node will eventually grow due to ongoing peer recoveries, restoring snapshots, and similar activities. A value of -1 indicates that this is not available.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.shards.size

The size of the shards assigned to this node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.thread_pool.tasks.finished

The number of tasks finished by the thread pool.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {tasks} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| thread_pool_name | The name of the thread pool. | Any Str | false |
| state | The state of the task. | Str: ``rejected``, ``completed`` | false |

### elasticsearch.node.thread_pool.tasks.queued

The number of queued tasks in the thread pool.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {tasks} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| thread_pool_name | The name of the thread pool. | Any Str | false |

### elasticsearch.node.thread_pool.threads

The number of threads in the thread pool.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {threads} | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| thread_pool_name | The name of the thread pool. | Any Str | false |
| state | The state of the thread. | Str: ``active``, ``idle`` | false |

### elasticsearch.node.translog.operations

Number of transaction log operations.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operations} | Sum | Int | Cumulative | true |

### elasticsearch.node.translog.size

Size of the transaction log.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.translog.uncommitted.size

Size of uncommitted transaction log operations.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.os.cpu.load_avg.15m

Fifteen-minute load average on the system (field is not present if fifteen-minute load average is not available).

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Double |

### elasticsearch.os.cpu.load_avg.1m

One-minute load average on the system (field is not present if one-minute load average is not available).

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Double |

### elasticsearch.os.cpu.load_avg.5m

Five-minute load average on the system (field is not present if five-minute load average is not available).

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Double |

### elasticsearch.os.cpu.usage

Recent CPU usage for the whole system, or -1 if not supported.

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| % | Gauge | Int |

### elasticsearch.os.memory

Amount of physical memory.

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| state | State of the memory | Str: ``free``, ``used`` | false |

### jvm.classes.loaded

The number of loaded classes

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Int |

### jvm.gc.collections.count

The total number of garbage collections that have occurred

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of the garbage collector. | Any Str | false |

### jvm.gc.collections.elapsed

The approximate accumulated collection elapsed time

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| ms | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of the garbage collector. | Any Str | false |

### jvm.memory.heap.committed

The amount of memory that is guaranteed to be available for the heap

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

### jvm.memory.heap.max

The maximum amount of memory can be used for the heap

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

### jvm.memory.heap.used

The current heap memory usage

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

### jvm.memory.nonheap.committed

The amount of memory that is guaranteed to be available for non-heap purposes

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

### jvm.memory.nonheap.used

The current non-heap memory usage

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

### jvm.memory.pool.max

The maximum amount of memory can be used for the memory pool

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of the JVM memory pool. | Any Str | false |

### jvm.memory.pool.used

The current memory pool memory usage

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| By | Gauge | Int |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| name | The name of the JVM memory pool. | Any Str | false |

### jvm.threads.count

The current number of threads

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Int |

## Optional Metrics

The following metrics are not emitted by default. Each of them can be enabled by applying the following configuration:

```yaml
metrics:
  <metric_name>:
    enabled: true
```

### elasticsearch.cluster.indices.cache.evictions

The number of evictions from the cache for indices in cluster.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {evictions} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| cache_name | The name of cache. | Str: ``fielddata``, ``query`` | false |

### elasticsearch.index.cache.evictions

The number of evictions from the cache for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {evictions} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| cache_name | The name of cache. | Str: ``fielddata``, ``query`` | false |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.cache.memory.usage

The size in bytes of the cache for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| cache_name | The name of cache. | Str: ``fielddata``, ``query`` | false |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.cache.size

The number of elements of the query cache for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| 1 | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.operations.merge.docs_count

The total number of documents in merge operations for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {documents} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.operations.merge.size

The total size of merged segments for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.segments.memory

Size of memory for segment object of an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |
| object | Type of object in segment | Str: ``term``, ``doc_value``, ``index_writer``, ``fixed_bit_set`` | false |

### elasticsearch.index.segments.size

Size of segments of an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.translog.operations

Number of transaction log operations for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operations} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.index.translog.size

Size of the transaction log for an index.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| aggregation | Type of shard aggregation for index statistics | Str: ``primary_shards``, ``total`` | false |

### elasticsearch.node.cache.size

Total amount of memory used for the query cache across all shards assigned to the node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### elasticsearch.node.operations.current

Number of query operations currently running.

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| {operations} | Gauge | Int |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| operation | The type of operation. | Str: ``index``, ``delete``, ``get``, ``query``, ``fetch``, ``scroll``, ``suggest``, ``merge``, ``refresh``, ``flush``, ``warmer`` | false |

### elasticsearch.node.operations.get.completed

The number of hits and misses resulting from GET operations.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| {operations} | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| result | Result of get operation | Str: ``hit``, ``miss`` | false |

### elasticsearch.node.operations.get.time

The time spent on hits and misses resulting from GET operations.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| ms | Sum | Int | Cumulative | true |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| result | Result of get operation | Str: ``hit``, ``miss`` | false |

### elasticsearch.node.segments.memory

Size of memory for segment object of a node.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

#### Attributes

| Name | Description | Values | Optional |
| ---- | ----------- | ------ | -------- |
| object | Type of object in segment | Str: ``term``, ``doc_value``, ``index_writer``, ``fixed_bit_set`` | false |

### elasticsearch.process.cpu.time

CPU time used by the process on which the Java virtual machine is running.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| ms | Sum | Int | Cumulative | true |

### elasticsearch.process.cpu.usage

CPU usage in percent.

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Double |

### elasticsearch.process.memory.virtual

Size of virtual memory that is guaranteed to be available to the running process.

| Unit | Metric Type | Value Type | Aggregation Temporality | Monotonic |
| ---- | ----------- | ---------- | ----------------------- | --------- |
| By | Sum | Int | Cumulative | false |

### jvm.memory.heap.utilization

Fraction of heap memory usage

| Unit | Metric Type | Value Type |
| ---- | ----------- | ---------- |
| 1 | Gauge | Double |

## Resource Attributes

| Name | Description | Values | Enabled |
| ---- | ----------- | ------ | ------- |
| elasticsearch.cluster.name | The name of the elasticsearch cluster. | Any Str | true |
| elasticsearch.index.name | The name of the elasticsearch index. | Any Str | true |
| elasticsearch.node.name | The name of the elasticsearch node. | Any Str | true |
| elasticsearch.node.version | The version of the elasticsearch node. | Any Str | true |
