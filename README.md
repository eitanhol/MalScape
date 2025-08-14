See the [Full Changelog](../../blob/main/CHANGELOG.md) for all updates.

## User-Visible Feature Additions

### File Upload (.parquet) & Demo Loader
- **How it works**: Upload a `.parquet` capture to initialize the app. Optionally, click **Load Demo File** to load a bundled example with the correct schema.
- **Why it matters**: Guarantees a fast, known-good path to explore the UI and verify visuals without hunting for data.
- **Implementation notes**: Frontend controls in **`index.html`** (`#fileInput`, `#loadDemoBtn`); handlers in **`script.js`** (upload flow, demo loader). Backend endpoints in **`app.py`**: `POST /process_uploaded_file`, `POST /load_demo_file`.

### Pre-processing Dashboard
- **How it works**: Immediately after a successful upload, the dashboard summarizes **total packets**, **data volume**, **unique sources/destinations**, and **top protocols**.
- **Why it matters**: Quick “size & shape” snapshot before choosing a time window or heavier analysis.
- **Implementation notes**: UI in **`index.html`** (`#initial-dashboard`), populated by **`script.js`** (`showInitialDashboard()` in the upload flow). Data from **`app.py`** `GET /summary_stats`.

### Timeline: Selection Window
- **How it works**: A draggable selection window lets you choose the time slice to process. You can type **manual start/end** and **apply**; **reset** returns to the initial bounds.
- **Why it matters**: Focus processing on the period of interest (large captures stay responsive).
- **Implementation notes**: Controls in **`index.html`** (`#timeline-card`, `#applyManualTimeBtn`, `#resetTimelineBtn`). Rendering & drag logic in **`script.js`**. Data from **`app.py`** `GET /timeline_data`.

### Timeline: Variable-Width First/Last Blocks
- **How it works**: Only the first and last timeline blocks shrink to reflect partial durations; inner blocks remain uniform.
- **Why it matters**: Prevents misreading partial intervals as full-duration blocks.
- **Implementation notes**: Drawn by the timeline renderer in **`script.js`**.

### Timeline: Processed-Range Marker
- **How it works**: A translucent outline indicates the **exact** processed interval, even if the selection window later moves.
- **Why it matters**: Keeps analysis context tied to the data actually processed.
- **Implementation notes**: Part of the timeline update path in **`script.js`**. Processed time metadata from **`app.py`** `GET /time_info`.

### Timeline: Tooltips
- **How it works**: Hovering a block shows packet counts and top talkers for that interval; attack-related items are highlighted.
- **Why it matters**: At-a-glance density and activity cues without leaving the timeline.
- **Implementation notes**: Tooltip template & show/hide logic in **`script.js`** using `GET /timeline_data`.

### Timeline: Granularity Control & Show/Hide
- **How it works**: Set the interval size (seconds) and **Apply**; optionally **Show/Hide Timeline** to get more canvas space.
- **Why it matters**: Match binning to the duration you’re inspecting; free screen real estate when you don’t need the timeline.
- **Implementation notes**: Controls in **`index.html`** (`#timelineGranularityInput`, `#applyGranularityBtn`, `#toggleTimelineBtn`). Backend respects `interval_ms` in `GET /timeline_data`.

### Skip Timeline Selection (Process Entire File)
- **How it works**: Toggle **Skip Timeline Selection** to process the entire upload in one go.
- **Why it matters**: One-click path when you want a whole-capture overview.
- **Implementation notes**: Toggle in **`index.html`** (`#skipTimelineSelectionToggle`); upload/initialize flow in **`script.js`**; processing in **`app.py`** `POST /initialize_main_view`.

---

### Inline Dendrogram + Heatmap (Main View)
- **How it works**: The app generates a hierarchical tree over clusters and renders an attached heatmap. Leaves correspond to clusters; features display as heatmap rows.
- **Why it matters**: Combines structure (tree) with detail (heatmap) to reveal related traffic patterns and where activity concentrates.
- **Implementation notes**: Container & controls in **`index.html`** (`#dendrogramCard`, `#treeControls`, `#inlineDendrogramSvg`). Data from **`app.py`** `GET /hierarchical_clusters`.

### Dendrogram: Resolution & Reclustering
- **How it works**: Enter a **Resolution** and **Apply** to recluster; recently created clusters are temporarily highlighted so you can see what changed.
- **Why it matters**: Lets you tune community detection granularity and immediately view the impact.
- **Implementation notes**: Controls in **`index.html`** (`#resolutionInput`, `#applyResolutionBtn`, `#acknowledgeNewClustersBtn`). Frontend in **`script.js`**; backend uses Louvain-based clustering in **`app.py`** (`compute_clusters()` called from `GET /hierarchical_clusters?resolution=`).

### Dendrogram: Reorder & Sorting
- **How it works**: **Reorder Tree Structure** toggles a metric-driven ordering; the **Sort Metric** and **Row Order** selectors adjust leaf order without altering the grouping.
- **Why it matters**: Reduces visual crossing and improves pattern readability in crowded trees.
- **Implementation notes**: Controls in **`index.html`** (`#reorderTreeCheckbox`, `#dendrogramSortMetricSelect`, `#rowOrderSelect`). Handlers in **`script.js`**.

### Dendrogram: Threshold Grouping (Cut)
- **How it works**: Set a displayed-percentage **Threshold** and **Apply** to collapse minor branches; **Reset Grouping** restores the full tree.
- **Why it matters**: De-clutters the canvas so salient groups stand out.
- **Implementation notes**: Controls in **`index.html`** (`#applyThresholdBtn`, `#resetGroupingBtn`); grouping logic in **`script.js`**.

### Cluster Drill-Down (Subtree)
- **How it works**: Select combined-cluster cells and click **Create Subtree** to generate a focused tree/heatmap for those items; **Back to Main Tree** returns.
- **Why it matters**: Multi-level exploration without losing the main context.
- **Implementation notes**: Controls in **`index.html`** (`#createSubtreeBtn`, `#backToMainTreeBtn`); data from **`app.py`** `POST /create_subtree`.

### Heatmap: Selection, Multi-Select, & Tooltips
- **How it works**: Click heatmap cells to select clusters (multi-select is supported by repeat clicks). Tooltips show the attack category when applicable.
- **Why it matters**: Fast target selection with immediate context for what’s flagged.
- **Implementation notes**: Selection & tooltip logic in **`script.js`**; attack labels originate from **`app.py`** (`/initialize_main_view`, `/filter_and_aggregate`).

### Metadata Line: Packet & Attack Counters
- **How it works**: The header line above the tree/heatmap shows totals for selected clusters, including anomalous (attack) packet counts.
- **Why it matters**: Quantifies impact without opening tables.
- **Implementation notes**: Computed in **`script.js`** using aggregated selection state.

---

### Sidebar Cluster Network, Protocol Legend & Table
- **How it works**: Selecting clusters opens the sidebar network for that selection. Nodes represent endpoints; edges represent flows with size driven by packet count or bytes. Selecting nodes or edges filters the **Sidebar Table** below. Multiple edges can be selected to load a combined table. The **Protocol Legend** in the sidebar lists each protocol, its assigned color, and its percentage share in the currently processed time range—helping you interpret edge colors and traffic composition.
- **Why it matters**: Lets you pivot from cluster-level patterns to concrete flow endpoints and inspect underlying packets. The protocol legend ties edge coloring directly to protocol identities, improving the ability to read the graph at a glance.
- **Implementation notes**: Sidebar container and controls in **`index.html`** (`#sidebar`, `#sidebar-cy`, `#sidebar-table-container`, `#legend`). Frontend logic in **`script.js`** (`visualizeClusterInSidebar()`, `bindSidebarGraphEvents()`, `loadSidebarMultiEdgeTable()`); backend data from **`app.py`** `GET /cluster_network`, `POST /get_multi_edge_table`, and `GET /protocol_percentages`.

### Sidebar Graph: Layout, Sizing, Reset, Fullscreen
- **How it works**: Choose a **layout**; adjust **node/edge size** ranges; **reset zoom** to re-center; switch the sidebar to **fullscreen**.
- **Why it matters**: Maintains readability as selections vary in size and complexity.
- **Implementation notes**: Controls in **`index.html`** (`#sidebarLayoutSelect`, `#sidebarNodeSizeMin`, `#sidebarNodeSizeMax`, `#sidebarEdgeWidthMin`, `#sidebarEdgeWidthMax`, `#resetSidebarZoomBtn`, `#sidebarFullscreenBtn`). Behavior in **`script.js`** (`applySidebarLayout()`, `applySidebarSizeControls()`).

### Sidebar Table: Search & Pagination
- **How it works**: The table supports **search** and **pagination**; clicking a row highlights the corresponding element(s) in the sidebar graph.
- **Why it matters**: Makes large flow subsets navigable and links records back to the visualization.
- **Implementation notes**: UI in **`index.html`** (`#sidebarTableSearchInput`, pagination controls). Frontend in **`script.js`**; rows come from **`app.py`** `POST /get_multi_edge_table`.

### Saved Items
- **How it works**: **Save Selection** stores the current cluster/group selection (including selected nodes) in the **Saved Items** list for quick return during the session.
- **Why it matters**: Bookmarks interesting findings while you continue exploring.
- **Implementation notes**: List UI in **`index.html`** (`#saved-items-list`, `#no-saved-items`). Managed in **`script.js`**.

---

### Configurable Multi-Dimension Sankey
- **How it works**: Build a Sankey diagram from multiple dimensions (e.g., **Protocol**, **Source/Destination Type**, **Src/Dst Port Group**, **Packet Length Group**, **Attack Status**, **Cluster ID**). Nodes represent categories within each chosen dimension, arranged in columns. Flows (links) between columns are weighted by packet count, visually showing how traffic moves from one category to another. You can click a node to filter the diagram to flows passing through it, and optionally **Apply to Heatmap** to highlight all clusters that match the filtered flow. A **Revert** button clears the Sankey filter and restores the full heatmap.
- **Why it matters**: Connects categorical attributes to each other and to cluster structure, making it easy to see relationships like “Which protocol and port group combinations are most common for attack traffic?” or “Which destination types carry the largest flows?” It allows analysts to spot unusual category pairings that may indicate suspicious or novel behaviors.
- **Implementation notes**: UI in **`index.html`** (`#sankeyCard`, `#sankeyDimensionCheckboxes`, `#showSankeyBtn`, `#applySankeyToHeatmapBtn`, `#revertSankeyFilterBtn`). Frontend in **`script.js`** (`buildSankeyDiagram()`, `applySankeySelectionToHeatmap()`); backend in **`app.py`** `POST /sankey_data` and `POST /get_sankey_matching_clusters`.

---

### Main Filters & Metrics (Heatmap Input)
- **How it works**: Global filters include **Payload keyword**, **Source/Destination/Protocol** contains, **Cluster entropy** min/max, and **unique endpoints per cluster** min/max. The **Metric** selector controls what the heatmap aggregates (e.g., **count**, **% SYN/RST/ACK/PSH packets**, **Unique Destinations/Sources/IPs**, **Payload Size Variance**, **Packets per Second**).
- **Why it matters**: Shapes the heatmap to surface clusters that matter for your task (volume, volatility, signaling, or fan-out).
- **Implementation notes**: Controls in **`index.html`** (`#mainFilterGroup` and related inputs). Frontend submits via **`script.js`**; aggregation in **`app.py`** `POST /filter_and_aggregate` (see `aggregate_metric()` for supported metrics).

### Magnifying Glass (Loupe)
- **How it works**: Toggle the loupe to display a circular zoomed-in view that follows the cursor. Adjust **zoom** with the numeric input.
- **Why it matters**: Inspect dense regions without losing global context or changing the current zoom.
- **Implementation notes**: Controls in **`index.html`** (`#magnifyingGlassBtn`, `#magnifyingGlassZoom`, `#magnifying-glass-controls`). Implemented in **`script.js`**.

### Reset Zoom Controls
- **How it works**: Dedicated buttons reset pan/zoom for both the **sidebar network** and the **inline tree/heatmap**.
- **Why it matters**: Prevents getting “lost” after heavy navigation.
- **Implementation notes**: Buttons in **`index.html`** (`#resetSidebarZoomBtn`, `#resetInlineZoomBtn`); handlers in **`script.js`**.