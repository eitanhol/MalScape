# Changelog
## [2025-06-03]
### Added
- Reorganize arrows to Sankey diagram

### In Progress
- Highlight heatmap clusters that are selected in Sankey diagram
- Added button to apply selected clusters

## [2025-06-02]
### Attempted
- Optimization of CSV processing

## [2025-06-01]
### Changed
- Sankey diagram now shows all dimensions

### Fixed
- Issue where anomaly infromation between heatmap and cluster view were inconsistent with large csv

## [2025-05-29]
### Changed
- Sankey diagram updates

## [2025-05-28]
### Added
- Started Sankey diagram

## [2025-05-27]
### Fixed
- Anomaly detection now considers the timeframe of the uploaded CSV

### Added
- Cancel button to loading screen

### Changed
- IP graph now uses PCA

## [2025-05-25]
### Added
- Started IP node graph

## [2025-05-24]
### Changed
- Node radius is now equal to square root of number of packets

## [2025-05-22]
### Fixed
- Sidebar table issue
- Saved items list behavior

## [2025-05-21]
### Added
- Functionality to save selected nodes to list


## [2025-05-18]
### Added
- Working deployment for small CSVs.

### Changed
- Slight optimizations to CSV processing for faster handling.

## [2025-05-16]
### Fixed
- New heatmap cells (previously gray with no metric data) now display correct metrics when high Louvain resolution is applied.

### Added
- Highlights for new clusters on the heatmap.
- Button to hide new cluster highlights.

### Changed
- Initial deployment setup started (some issues remain).

## [2025-05-15]
### Added
- Display of attack type in tooltips.
- Deselect functionality in the cluster view by clicking on empty space.
- Handling of new connections between nodes when combining clusters using threshold.

### Fixed
- Fullscreen toggle behavior.
- Multi-node selection in the network visualization.

### Changed
- Removed unhelpful filters.
- Grayed out "Order Cells by Filter" option when not applicable.
