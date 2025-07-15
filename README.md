# Changelog

## [2025-07-14]
### Fixed
- Sankey "Apply to heatmap" button not working with new selection functionality from 6/23
- Holding Control before starting timeline window drag not working
- Timeline tooltips not showing

### Added
- Option to choose timeline block granularity in milliseconds, with an "Apply" button

### Improved
- Alignment on timeline input boxes

## [2025-07-10]
### Fixed
- "Create sub tree from selection" button not hiding after clicking "Reset node selection"
- Listing of packets from selected clusters not hiding after clicking "Reset node selection"
- Timeline input boxes being empty before making a change

### Added
- Caching to timeline data to optimize visualization speed

### Improved
- Can now hold Control while dragging the timeline window to lock onto edges of timeline blocks (does not yet work if Control is held before dragging)

## [2025-07-09]
### Added
- Listing of total anomalous packets from selected clusters

### Fixed
- Heatmap cell colors after "Create sub tree from selection"

## [2025-07-08]
### Added
- List number of packets from all selected clusters

### Changed
- Sidebar only opens if there are no previous clusters selected

## [2025-07-07]
### Added
- Toggle magnifying glass button
- Input box for magnifying glass zoom

## [2025-07-04]
### Fixed
- Timeline tooltips going off screen

### Changed
- Timeline edge blocks now have variable width, and their height is proportional to the amount of data taking their length into account

### Improved
- Timeline tooltips are hidden while dragging timeline selection

## [2025-07-03]
### Fixed
- Issue with heatmap cell colors after reset grouping

### Added
- Transparent border to processed timeframe on timeline

## [2025-07-01]
### Fixed
- Show Sankey diagram being enabled after processing a new file
- Only processed timeline section showing after processing
- Attacks not showing on timeline after processing

## [2025-06-30]
### Fixed
- Timeline input box "Apply" button not staying grayed out with invalid inputs

## [2025-06-27]
### Improved
- Accuracy of anomaly detection on timeline

### Added
- Timeline tooltips

### Fixed
- File processing bug

## [2025-06-26]
### Fixed
- Completed fix of anomaly detection not working for some files

### Improved
- Show more accurate attack times on timeline after file processing

## [2025-06-25]
### Attempted
- Attempted to fix anomaly detection with certain files

## [2025-06-24]
### Added
- Input boxes for manual timeline selection
- "Reset timeline selection" button before file processing

### Fixed
- "Apply manual time" button remains grayed out until a valid change is made
- Timeline reset button behavior after file processing
- Number of packets displayed not updating after timeline selection change
- "Show Sankey diagram" and "Show timeline" buttons not hiding after uploading a second file
- "Apply manual time" button not graying out after uploading second file

## [2025-06-23]
### Added
- Functionality for the Sankey diagram to visually represent the proportion of traffic in each link that relates to a user's selection

## [2025-06-19]
### Added
- "Load demo file" button to allow users without a Parquet file to test the app
- Button to show/hide timeline
- Placeholder to max node size input box when no cluster is selected

### Fixed
- Timeline resize after closing sidebar
- Max node size shown in input box not resetting when cluster is deselected
- All nodes in anomalous cluster having red outline in combined cluster
- Visual bugs applying timeline threshold after file processing

### Changed
- Separated `malscapedev.html` into `index.html`, `styles.css`, and `script.js`
- Timeline colors adjusted for better visibility

### Improved
- Timeline now maintains selected threshold after file processing
- Timeline auto-hides after file processing
- Timeline give orange color to sections with attacks
- Sidebar hide button now hidden before file is processed

## [2025-06-18]
### Added
- Functionality to select timeline before processing file
- Title to timeline Y-axis
- Switch to let user select whether to process entire file or a specific timeframe

### Changed
- Timeline data preview adjusted to show more granular time intervals

### Improved
- UI Filters and buttons hidden before file is processed

## [2025-06-17]
### Added
- Functionality to view new tree and heatmap of all clusters from inside a combined cluster

## [2025-06-16]
### Fixed
- New heatmap clusters having no color and missing tooltip data
- Timeline sizing issues when opening sidebar

### Updated
- Display data on top of tree card when changing timeline

## [2025-06-12]
### Added
- Adjustable timeline of uploaded data

## [2025-06-11]
### Added
- Max node size input box now controls max node size in visualization

### Fixed
- Tooltips not showing in sidebar fullscreen mode
- Sidebar table search now searches all pages
- Red bar placement corrected after applying threshold

## [2025-06-10]
### Fixed
- Heatmap cell colors after applying threshold
- Combined cluster nodes not showing original cluster colors
- Reorder heatmap resetting cluster grouping

### Added
- Heatmap cell tooltips for combined clusters now list number of original clusters
- Anomalous nodes now have proportional red outlines for better visibility on large nodes

### In Progress
- Show on Sankey diagram selection how much is selected in all other sections

## [2025-06-09]
### Changed
- Converter tool now creates Parquet files with a `count` column that combines identical packets occurring consecutively within 1 second

## [2025-06-05]
### Fixed
- Parquet version compatibility issues

### Improved
- Sankey filters
- Sankey diagram selections now reflected on heatmap

## [2025-06-04]
### Added
- Implementation started for optimized CSV reading
- Packet count and process time display
- Tool to convert PCAP to Parquet

### Changed
- Top-level tree diagram info

### Created
- Parquet-compatible version with faster processing and much smaller file sizes

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
