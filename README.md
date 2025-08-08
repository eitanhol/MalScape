See the [Full Changelog](CHANGELOG.md) for all updates.

## User-Visible Feature Additions


### Pre-processing Dashboard
- **How it works**: Right after a file upload, the app requests capture-wide stats and populates the cards in `#initial-dashboard` (total packets, data volume, unique IPs, top protocols).
- **Why it matters**: Gives a quick “size & shape” snapshot before picking a timeline window or doing heavier analysis.
- **Implementation notes**: Backend route in **`app.py`** (`/summary_stats`). Markup in **`index.html`** (`#initial-dashboard` and `#stat-*` IDs). Client code in **`script.js`** (`showInitialDashboard()` + the upload flow).

### Reset Zoom Controls
- **How it works**: Two buttons reset zoom/pan: **Sidebar graph** (`#resetSidebarZoomBtn`) and **inline tree/heatmap** (`#resetInlineZoomBtn`).
- **Why it matters**: Prevents users from getting “lost” after aggressive zoom/pan in dense visuals.
- **Implementation notes**: Handlers and helpers in **`script.js`** (`resetSidebarZoom()` and `resetInlineZoom()`). Buttons declared in **`index.html`** next to the respective visual headers.

### Packet & Attack Counters on Selection
- **How it works**: When clusters are selected, the app totals both their packet counts and attack-packet counts and shows them in the tree metadata line.
- **Why it matters**: Gives a quick sense of overall and attack-specific volumes without opening the packet table.
- **Implementation notes**: Uses `aggregatedLeafData` in **`script.js`** to compute totals; rendered by the metadata update routine for the inline tree/heatmap.

### Magnifying Glass (Loupe)
- **How it works**: Toggleable loupe overlays a circular zoomed view anywhere in the program. Zoom factor is adjustable via an input next to the toggle.
- **Why it matters**: Inspect congested or detailed areas without losing global context.
- **Implementation notes**: Implemented in **`script.js`** (creation/toggle + zoom input). Controls are in **`index.html`** (`#magnifyingGlassBtn`, `#magnifyingGlassZoom`).

### Variable-Width Timeline Edge Blocks
- **How it works**: Only the first and last timeline blocks adjust their width to match their shorter duration, while all other blocks remain uniform.
- **Why it matters**: Correctly represents partial-duration edge blocks instead of misleadingly showing them as equal in time.
- **Implementation notes**: Drawn in **`script.js`** by the timeline renderer.

### Processed-Range Marker
- **How it works**: A semi-transparent outline marks the processed interval on the timeline.
- **Why it matters**: Shows exactly what slice is currently analysed, even if you move the selection window without reprocessing.
- **Implementation notes**: Part of the timeline render/update logic in **`script.js`**.

### Timeline Tooltips (Enhanced)
- **How it works**: Hovering a timeline block shows packet count, number of attack packets, top talkers, and whether attacks are present. If an attack IP is in the top 3, it is colored orange.
- **Why it matters**: Gives richer at-a-glance context for each timeline block.
- **Implementation notes**: Tooltip template + show/hide logic in the timeline code path in **`script.js`**.

### Manual Timeline Inputs, Reset & Validation
- **How it works**: Start/End inputs allow precise windows. “Apply” stays disabled until inputs are valid; “Reset” clears to defaults.
- **Why it matters**: Enables pin-point forensics and prevents off-by-one errors from drag-selections.
- **Implementation notes**: Inputs and buttons in **`index.html`** (timeline card). Validation/apply/reset handlers in **`script.js`**.

### Sankey → Heatmap Selection Sync (Improved)
- **How it works**: Selecting nodes or links in the Sankey and applying highlights marks all heatmap clusters carrying that traffic; a revert clears highlights. Sankey nodes with value of 0 are hidden, and small nodes are easier to select.
- **Why it matters**: Connects flow analysis in the Sankey to anomaly/cluster views while improving clarity and usability.
- **Implementation notes**: UI buttons in **`index.html`**. Client logic in **`script.js`** (tracks `currentSankeyDimensionsOrder`, collects selected nodes/links, calls the server to resolve matching ClusterIDs, then highlights those heatmap cells). Server endpoints in **`app.py`** (`/sankey_dimensions_meta`, `/sankey_data`, `/get_sankey_matching_clusters`).

### Show/Hide Timeline Toggle
- **How it works**: A button collapses/expands the timeline card with a smooth transition.
- **Why it matters**: Frees vertical space on smaller screens once a window is chosen.
- **Implementation notes**: Toggle button and card live in **`index.html`**; event handler in **`script.js`**.

### Demo File Loader
- **How it works**: "Load Demo File" uploads a bundled real-world sample in the correct format without needing to locate or convert a file.
- **Why it matters**: Saves setup time. Normally you’d have to use a separate conversion tool to prepare a file; this lets you explore/test immediately.
- **Implementation notes**: Button in **`index.html`**; handler in **`script.js`**; sample file path referenced in the handler.

### Pre-processing Timeline Selection Workflow
- **How it works**: Upload → adjust/confirm timeline window → process. A **Skip Timeline Selection** toggle processes the entire file instead.
- **Why it matters**: Slashes processing time on large captures, while keeping a one-click path.
- **Implementation notes**: Toggle and inputs in **`index.html`** (`#skipTimelineSelectionToggle`). Upload flow and parameter passing in **`script.js`** (`handleFileUpload` → adds start/end params when present).

### Cluster Drill-Down (Sub-Tree) View
- **How it works**: Select combined-cluster cells and click **Create Sub-Tree from Selection**. A focused tree/heatmap view is generated for just those leaves. **Back to Main Tree** restores the original view.
- **Why it matters**: Enables multi-level exploration without cluttering the main canvas.
- **Implementation notes**: Buttons in **`index.html`** (`#createSubtreeBtn`, `#backToMainTreeBtn`). Client logic in **`script.js`** (sub-tree generation & state swaps). Tree data comes from **`app.py`** (`/hierarchical_clusters`).

### Adjustable Timeline Window
- **How it works**: Drag the selection window on the timeline header to refine bounds; you must reprocess to apply the new window.
- **Why it matters**: Allows iterative narrowing to suspect periods, with new processing runs for each change.
- **Implementation notes**: Timeline selection/drag code lives in **`script.js`**.

### Max Node Size (Main Graph)
- **How it works**: Numeric inputs set min/max node radius and edge width in the **main** Cytoscape graph; there’s no default hardcoded max—users must enter one to apply a limit.
- **Why it matters**: Prevents “elephant” nodes/edges from dwarfing the scene in sparse captures.
- **Implementation notes**: Controls in **`index.html`** (main graph sizing inputs). Logic in **`script.js`** (`applySizeControls()` for the main graph; `applySidebarSizeControls()` for the sidebar graph).

### Configurable Multi-Dimension Sankey
- **How it works**: The Sankey can be built from multiple categorical dimensions (Protocol, Source/Dest Type, Port Groups, Packet Length Group, Attack status, optional Cluster ID). Checkboxes/toggles control which layers appear and in what order.
- **Why it matters**: Avoids hard-coded diagrams and supports future dimensions.
- **Implementation notes**: Dimension metadata fetched from the server; UI state kept in `currentSankeyDimensionsOrder` in **`script.js`**; graph data from `/sankey_data` in **`app.py`**.

### Initial Sankey Diagram
- **How it works**: First D3 Sankey rendering showing flows across selected dimensions.
- **Why it matters**: Provides a holistic flow view that complements the cluster-centric heatmap.
- **Implementation notes**: Built and updated entirely from **`script.js`**.

### Node-Radius Scaling (Sidebar Graph)
- **How it works**: In the **sidebar** graph, node diameter scales to √(packet count), clamped by user min/max inputs; attacker nodes get proportionally thicker borders.
- **Why it matters**: Keeps dense side-graphs readable while still conveying magnitude.
- **Implementation notes**: Logic in **`script.js`** (`applySidebarSizeControls()`); inputs live in **`index.html`** (Sidebar Graph Sizing panel).

### Saved Items List
- **How it works**: A “Save Selection” button bookmarks the current selection of clusters/IPs to a **Saved Items** list. The list persists between sessions.
- **Why it matters**: Lets analysts queue items to revisit without re-searching.
- **Implementation notes**: Markup in **`index.html`** (Saved Items section in the legend). CRUD and persistence in **`script.js`** (localStorage + render/update helpers). “Reset Node Selection” clears both highlights and related table state.

### New-Cluster Highlighter
- **How it works**: After reclustering (e.g., changing Louvain resolution), clusters with new IDs are temporarily highlighted on the heatmap and fade on interaction.
- **Why it matters**: Makes reclassification effects instantly visible.
- **Implementation notes**: Implemented in **`script.js`** as part of the heatmap refresh path.

### Attack Tooltips & Multi-Select
- **How it works**: Heatmap cells show attack category in a tooltip; selecting multiple is done with repeated left-clicks, and clicking again deselects.
- **Why it matters**: Richer context and smoother UX during exploratory analysis.
- **Implementation notes**: Tooltip assembly and selection handling live with the heatmap code in **`script.js`**.