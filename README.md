[![Go](https://github.com/geolffreym/rolling-sync/actions/workflows/go.yml/badge.svg)](https://github.com/geolffreym/rolling-sync/actions/workflows/go.yml)

# Rolling Hash Algorithm

_Spec v5 (2022-04-04)_

(Patch API not implemented)

Make a rolling hash based file diffing algorithm. When comparing original and an updated version of an input, it should return a description ("delta") which can be used to upgrade an original version of the file into the new file. The description provides information of the chunks which:

- Can be reused from the original file
- Have been added or modified and thus would need to be synchronized

The real-world use case for this type of construct could be a distributed file storage system. This reduces the need for bandwidth and storage. If user has a local copy of a file stored in the cloud, then changes between these two instances can be synchronized using diff produced by rolling hash.

## Requirements

- Hashing function gets the data as a parameter. Separate possible filesystem operations.
- Chunk size can be fixed or dynamic, but must be split to at least two chunks on any sufficiently sized data.
- Should be able to recognize changes between chunks. Only the exact differing locations should be added to the delta.
- Well-written unit tests function well in describing the operation, no UI necessary.

## Checklist

1. Input/output operations are separated from the calculations
2. detects chunk changes and/or additions
3. detects chunk removals
4. detects additions between chunks with shifted original chunks

## Usage

Run Tests:  `make test`

Build: `make build`

Test Coverage: `make coverage`

Benchmark: `make benchmark`

Code Analysis: `make check`

clean up directory: `make clean`


