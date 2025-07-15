//GLOBAL
    let API_BASE_URL;
    if (window.location.hostname === "127.0.0.1" && 
        (window.location.port === "5500" || window.location.port === "5501" || window.location.port === "5502" /* Add other common Live Server ports if needed */) &&
        window.location.port !== "5000") {
        API_BASE_URL = 'http://127.0.0.1:5000'; // Manually target Flask server
        console.log("Detected local Live Server, API_BASE_URL forced to Flask default:", API_BASE_URL);
    } else {
        API_BASE_URL = window.location.origin; // Standard behavior for deployment or when served by Flask
        console.log("Using window.location.origin for API_BASE_URL:", API_BASE_URL);
    }

    const DEFAULT_SANKEY_DIMENSIONS = [
        { value: "Protocol", label: "Protocol", defaultChecked: true },
        { value: "SourceClassification", label: "Source Type", defaultChecked: true },
        { value: "DestinationClassification", label: "Dest. Type", defaultChecked: true },
        { value: "SourcePort_Group", label: "Src Port Grp", defaultChecked: true },
        { value: "DestinationPort_Group", label: "Dst Port Grp", defaultChecked: true },
        { value: "Len_Group", label: "Pkt Len Grp", defaultChecked: true },
        { value: "Anomaly", label: "Anomaly", defaultChecked: true },
        { value: "ClusterID", label: "Cluster ID", defaultChecked: false }
    ];
    window.currentSankeyDimensionsOrder = [...DEFAULT_SANKEY_DIMENSIONS];
    window.sankeyMatchingClusterIds = new Set();
    window.activeSankeyFilter = null;

    window.fullTimelineData = null;

    const DEFAULT_UNKNOWN_COLOR = '#cccccc';
    const SELECTED_EDGE_COLOR = '#ff0000';
    const SELECTED_NODE_COLOR = '#ff0000';
    const SELECTED_EDGE_WIDTH = 3.5;
    const SELECTED_EDGE_ZINDEX = 999;

    let sankeyDiagramRendered = false;
    let globalAbortController = new AbortController();
    let louvainIpCy = null;
    window.currentGroupingApplied = false;
    window.lastAppliedThreshold = 100;
    window.originalTreeData = null;
    window.currentGrouping = null;
    let previousClusterCount = null;
    let previousClusterHash = null;
    let currentDendrogramHeight = 400;
    window.lastTreeData = null;
    window.inlineZoom = null;
    let initialTreeTransform = d3.zoomIdentity;
    const margin = { top: 30, right: 30, bottom: 120, left: 30 };
    window.fullHeatmapData = {};
    window.heatmapSortOrders = {};
    const metrics = [
        { label: "Count", value: "count" }, { label: "Unique IPs", value: "Unique IPs" },
        { label: "Unique Sources", value: "Unique Sources" }, { label: "Unique Destinations", value: "Unique Destinations" },
        { label: "Packet Length", value: "Length" }, { label: "Payload Length", value: "PayloadLength" },
        { label: "Payload Size Variance", value: "Payload Size Variance" },
        { label: "Start Time", value: "Start Time" },
        { label: "Duration", value: "Duration" },
        { label: "Average Inter-Arrival Time", value: "Average Inter-Arrival Time" },
        { label: "Packets per Second", value: "Packets per Second" },
        { label: "Total Data Sent", value: "Total Data Sent" },
        { label: "% SYN packets", value: "% SYN packets" }, { label: "% RST packets", value: "% RST packets" },
        { label: "% ACK packets", value: "% ACK packets" }, { label: "% PSH packets", value: "% PSH packets" }
    ];

    var currentDisplayableTimeInfo = {
        start: "Start: N/A",
        end: "End: N/A",
        duration: "Duration: N/A",
        isSet: false
    };

    let protocolColorMap = {};
    let globalCy;
    let sidebarCy;
    let currentClusterID = null;
    let currentSidebarTableClusterId = null;
    const TABLE_PAGE_SIZE = 30;
    const heatmapCellWidth = 2;
    const heatmapCellHeight = 15;
    let tooltip;
    let clusterHighlightColors = new Map();
    let addedSidebarClusters = new Set();
    let selectedSidebarEdges = new Set();
    let selectedSidebarNodes = new Set();
    let previousClusterIdsBeforeRecluster = new Set(); //previous clusters before applying new louvain resolution
    let currentNewClusterIds = new Set();
    let selectedNodeId = null;
    let sidebarTableMode = 'cluster';
    let isSidebarOpen = false;
    const sidebarWidth = 500;
    const legendWidth = 220;
    
    window.activeSankeyNodeFilter = null;
    window.allClusterIdsMasterList = [];
    window.currentTimeSelection = null;

    let mainTreeViewBeforeSubtree = null;
    let isSubtreeViewActive = false;
    
    const sidebar = document.getElementById('sidebar');
    const sidebarToggleBtn = document.getElementById('sidebar-toggle');
    const mainContainer = document.getElementById('main-container');
    const legendContainer = document.getElementById('legend-container');
    const resetSidebarBtn = document.getElementById('resetSidebarBtn');
    const sidebarTableContainer = document.getElementById('sidebar-table-container');
    const sidebarTablePagination = document.getElementById('sidebar-table-pagination');
    const sidebarGoPageBtn = document.getElementById('sidebarGoPageBtn');
    const sidebarSearchContainer = document.getElementById('sidebar-table-search-container');
    const sidebarSearchInput = document.getElementById('sidebarTableSearchInput');
    const sidebarInfoDiv = document.getElementById('sidebar-info');
    const sidebarFullscreenBtn = document.getElementById('sidebarFullscreenBtn');
    let isSidebarFullscreen = false;
    let savedItems = [];
    const MAX_SAVED_ITEMS = 10;


    const sidebarLayoutOptions = {
        cose: {
            name: 'cose', animate: true, animationDuration: 500, padding: 30,
            idealEdgeLength: 100, nodeRepulsion: node => node.degree() * 15000,
            edgeElasticity: edge => 100, gravity: 60, numIter: 1000,
            initialTemp: 200, coolingFactor: 0.95, minTemp: 1.0, fit: true
        },
        breadthfirst: {
            name: 'breadthfirst', directed: true, padding: 20, circle: false,
            grid: false, spacingFactor: 1.4, avoidOverlap: true,
            nodeDimensionsIncludeLabels: false, roots: undefined,
            animate: true, animationDuration: 500, fit: true
        },
        circle: {
            name: 'circle', padding: 25, avoidOverlap: true,
            nodeDimensionsIncludeLabels: false, spacingFactor: 1.2, radius: undefined,
            startAngle: 3/2 * Math.PI,
            animate: true, animationDuration: 500, fit: true
        },
        grid: {
            name: 'grid', padding: 25, avoidOverlap: true,
            nodeDimensionsIncludeLabels: false, spacingFactor: 1,
            rows: undefined, cols: undefined,
            position: function( node ){},
            animate: true, animationDuration: 500, fit: true
        },
        concentric: {
            name: 'concentric', fit: true, padding: 30, startAngle: 3 / 2 * Math.PI,
            sweep: undefined, clockwise: true, equidistant: false,
            minNodeSpacing: 20, avoidOverlap: true, nodeDimensionsIncludeLabels: false,
            concentric: function( node ){ return node.degree(); },
            levelWidth: function( nodes ){ return nodes.maxDegree() / 4; },
            animate: true, animationDuration: 500
        }
    };

    function applySidebarLayout() {
        if (!sidebarCy) {
            console.log("Sidebar graph not initialized yet.");
            return;
        }
        const selectedLayoutName = document.getElementById('sidebarLayoutSelect').value;
        const layoutConfig = sidebarLayoutOptions[selectedLayoutName];

        if (!layoutConfig) {
            console.error(`Layout configuration for '${selectedLayoutName}' not found.`);
            return;
        }

        console.log(`Applying sidebar layout: ${selectedLayoutName}`);
        let layout = sidebarCy.layout(layoutConfig);
        layout.run();
    }

    function resetHeatmapHighlights() {
        // Select all heatmap cells within the dendrogram SVG
        const cells = d3.selectAll("#inlineDendrogramSvg .heatmap-cell");

        cells.each(function() {
            const cell = d3.select(this);
            // Get the original fill color stored when the cell was first drawn
            const originalFill = cell.attr("data-original-fill");
            const defaultStrokeColor = '#fff';
            const defaultStrokeWidth = 0.2;

            if (originalFill) {
                // Revert to the original color and default stroke
                cell.transition().duration(150)
                    .attr("fill", originalFill)
                    .style("stroke", defaultStrokeColor)
                    .style("stroke-width", defaultStrokeWidth);
            }
        });
        console.log("Heatmap cell highlights reset on client-side.");
    }

    function toggleSidebar(forceOpen = null) {
        const shouldBeOpen = forceOpen !== null ? forceOpen : !isSidebarOpen;
        // const timelineCard = document.getElementById('timeline-card'); // No longer needed here
        const mainContainer = document.getElementById('main-container');

        if (shouldBeOpen) {
            if (!isSidebarOpen) {
                legendContainer.classList.add('visible');
                sidebar.classList.add('open');
                isSidebarOpen = true;
                sidebarToggleBtn.innerHTML = '&times;';
                sidebarToggleBtn.style.left = `${legendWidth + sidebarWidth}px`;
                mainContainer.style.marginLeft = `${legendWidth + sidebarWidth}px`;
                
                // The logic to hide the timeline card has been removed.

                setTimeout(() => {
                    if (sidebarCy) {
                        sidebarCy.resize();
                        applySidebarLayout();
                        sidebarCy.fit(null, 30);
                    }
                }, 350);
            }
        } else {
            if (isSidebarOpen) {
                legendContainer.classList.remove('visible');
                sidebar.classList.remove('open');
                isSidebarOpen = false;
                sidebarToggleBtn.innerHTML = '&#9776;';
                sidebarToggleBtn.style.left = `0px`;
                mainContainer.style.marginLeft = `0px`;
                
                // Redraw the timeline after the sidebar's closing transition (0.3s) is complete
                setTimeout(() => {
                    const timelineCard = document.getElementById('timeline-card');
                    if (timelineCard && timelineCard.style.display !== 'none') {
                        drawTimeline();
                    }
                }, 350);
            }
        }
    }

    resetSidebarBtn.addEventListener('click', () => {
        console.log("Resetting sidebar view and heatmap highlights.");
        clearSidebarVisualization();
        updateLegend();
        selectedNodeId = null;
        document.getElementById('sidebarLayoutSelect').value = 'cose';
    });

    function showSidebarLoading(isLoadingGraph, isLoadingTable) {
        document.getElementById('sidebar-cy-loading').style.display = isLoadingGraph ? 'block' : 'none';
        document.getElementById('sidebar-table-loading').style.display = isLoadingTable ? 'block' : 'none';
        const showInfo = !isLoadingGraph && !isLoadingTable && (!sidebarCy || sidebarCy.elements().length === 0) && selectedSidebarEdges.size === 0 && selectedNodeId === null;
         sidebarInfoDiv.style.display = showInfo ? 'block' : 'none';
    }

    function filterSidebarTable() {
        // This function now triggers a reload of the table from the backend.
        const searchQuery = sidebarSearchInput.value || "";
        const page = 1; // Always reset to page 1 for a new search

        if (sidebarTableMode === 'cluster' && currentSidebarTableClusterId) {
            loadSidebarClusterTable(currentSidebarTableClusterId, page, searchQuery);
        } else if (sidebarTableMode === 'edges') {
            let edgeList = [];
            if (selectedSidebarNodes.size > 0 && sidebarCy) {
                 selectedSidebarNodes.forEach(nodeId => {
                    const node = sidebarCy.getElementById(nodeId);
                    if(node && node.length > 0) {
                        node.connectedEdges().forEach(edge => {
                           edgeList.push({
                                source: edge.data('source'),
                                destination: edge.data('target'),
                                protocol: edge.data('Protocol')
                           });
                        });
                    }
                 });
                 edgeList = Array.from(new Set(edgeList.map(JSON.stringify)), JSON.parse);
            } else if (selectedSidebarEdges.size > 0) {
                edgeList = Array.from(selectedSidebarEdges).map(key => {
                    const parts = key.split('|');
                    return { source: parts[0], destination: parts[1], protocol: parts[2] };
                });
            }

            if (edgeList.length > 0) {
                loadSidebarMultiEdgeTable(edgeList, page, searchQuery);
            } else {
                sidebarTableContainer.innerHTML = '<p style="padding: 10px; text-align: center;">Select a node or edge to search.</p>';
            }
        }
    }

    function handleSidebarTableRowClick(event) {
        if (!sidebarCy || event.target.tagName !== 'TD') {
            return;
        }

        const row = event.target.closest('tr');
        if (!row || !row.parentElement || row.parentElement.tagName !== 'TBODY') {
             console.log("Clicked outside table body row.");
             return;
        }

        const table = row.closest('table');
        if (!table) return;

        const headerCells = Array.from(table.querySelectorAll('thead th'));
        const dataCells = Array.from(row.querySelectorAll('td'));

        let sourceIndex = -1;
        let destIndex = -1;
        let protocolIndex = -1;

        headerCells.forEach((th, index) => {
            const headerText = th.textContent.trim();
            if (headerText === 'Source') sourceIndex = index;
            else if (headerText === 'Destination') destIndex = index;
            else if (headerText === 'Protocol') protocolIndex = index;
        });

        if (sourceIndex === -1 || destIndex === -1 || protocolIndex === -1) {
            console.error("Could not find Source, Destination, or Protocol columns in the sidebar table header.");
            return;
        }

        const source = dataCells[sourceIndex]?.textContent.trim();
        const destination = dataCells[destIndex]?.textContent.trim();
        const protocol = dataCells[protocolIndex]?.textContent.trim();

        if (!source || !destination || !protocol) {
            console.error("Could not extract valid source, destination, or protocol from table row.", { source, destination, protocol });
            return;
        }

        console.log(`Table row clicked. Finding edge: ${source} -> ${destination} [${protocol}]`);

        const edgeSelector = `edge[source = "${source}"][target = "${destination}"][Protocol = "${protocol}"]`;
        const edgeToSelect = sidebarCy.elements(edgeSelector);

        if (edgeToSelect.length > 0) {
            console.log("Edge found:", edgeToSelect.id());
            deselectCurrentNode();

            sidebarCy.edges().filter(edge => edge !== edgeToSelect.first()).forEach(edge => {
                 selectedSidebarEdges.delete(`${edge.data('source')}|${edge.data('target')}|${edge.data('Protocol')}`);
                 const originalColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                 const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                 edge.style({ 'line-color': originalColor, 'target-arrow-color': originalColor, 'width': originalWidth, 'z-index': 1 });
                 edge.unselect();
            });

            const targetEdge = edgeToSelect.first();
            const edgeKey = `${source}|${destination}|${protocol}`;
            selectedSidebarEdges.add(edgeKey);
            targetEdge.style({
                 'line-color': SELECTED_EDGE_COLOR,
                 'target-arrow-color': SELECTED_EDGE_COLOR,
                 'width': SELECTED_EDGE_WIDTH,
                 'z-index': SELECTED_EDGE_ZINDEX
            });
            sidebarCy.elements().unselect();
            targetEdge.select();

            sidebarCy.animate({
                fit: {
                    eles: targetEdge.union(targetEdge.connectedNodes()),
                    padding: 70
                },
                duration: 400
            });
             updateSidebarTableForSelectedEdges();

        } else {
            console.warn(`Edge not found in sidebar graph for: ${source} -> ${destination} [${protocol}]`);
        }
    }

    function clearSidebarVisualization() {
        if (sidebarCy) {
            sidebarCy.destroy();
            sidebarCy = null;
        }
        document.getElementById('sidebar-cy').innerHTML = '';
        addedSidebarClusters.clear();
        selectedSidebarEdges.clear();
        selectedNodeId = null;
        sidebarTableMode = 'cluster';
        currentSidebarTableClusterId = null;
        sidebarTableContainer.innerHTML = '<p id="sidebar-table-no-results" style="display: none; text-align: center; padding: 10px; color: #6c757d;">No rows match your search criteria.</p>';
        sidebarTableContainer.style.display = 'none';
        sidebarTablePagination.style.display = 'none';
        sidebarSearchContainer.style.display = 'none';
        if (sidebarSearchInput) sidebarSearchInput.value = '';
        document.getElementById('sidebar-cy-loading').style.display = 'none';
        document.getElementById('sidebar-table-loading').style.display = 'none';
        sidebarInfoDiv.innerHTML = 'Click a cell on the heatmap to add its cluster. Click nodes or edges in the graph to highlight and filter the table below.';
        sidebarInfoDiv.style.display = 'block';

        clusterHighlightColors.clear(); // Clear the central selection state map
        try {
            const svgContent = d3.select("#inlineDendrogramSvg g"); // Select the content group
            if (!svgContent.empty()) {

                highlightTreeClusters(); // Calling with no arguments resets fills

                const defaultStrokeColor = '#fff'; // Define or ensure access to default color
                const defaultStrokeWidth = 0.2;   // Define or ensure access to default width

                svgContent.selectAll('.heatmap-cell') // Select all heatmap cells within the dendro SVG
                    .transition().duration(150) // Use a short transition for smoothness
                    .style("stroke", defaultStrokeColor) // Set stroke color to default
                    .style("stroke-width", defaultStrokeWidth); // Set stroke width to default

                console.log("Reset tree node highlights AND tree-attached heatmap cell outlines.");
            }
        } catch (error) {
            console.error("Error resetting tree elements:", error);
        }
        
        updateSubtreeButtonState();

        // Reset Sidebar Layout Dropdown
        document.getElementById('sidebarLayoutSelect').value = 'cose';
        
        // Reset the placeholder for the max node size input
        const maxNodeSizeInput = document.getElementById('sidebarNodeSizeMax');
        if (maxNodeSizeInput) {
            maxNodeSizeInput.placeholder = "Largest node size = N/A";
            maxNodeSizeInput.value = ""; // Also clear any user-entered value
        }

        if (typeof window.updateDendrogramMetadata === 'function') {
            window.updateDendrogramMetadata();
        }

        console.log("Sidebar visualization, color map, selections, table, and related highlights cleared.");
    }

    // Helper function to reset main heatmap highlights
    function resetHeatmapHighlights() {
        console.log("Resetting main heatmap cell highlights.");
        d3.selectAll('#heatmap rect.cell').each(function() { // Target only main heatmap cells
            const cell = d3.select(this);
            const originalColor = cell.attr("data-original-fill"); // Read stored original color
            if (originalColor) { cell.attr("fill", originalColor); }
            else { cell.style("fill", null); }
        });
    }

    // Helper function to reset main heatmap highlights (called by clearSidebarVisualization)
    function resetHeatmapHighlights() {
        console.log("Resetting main heatmap cell highlights.");
        d3.selectAll('#heatmap rect.cell').each(function() { // Target only main heatmap cells
            const cell = d3.select(this);
            const originalColor = cell.attr("data-original-fill"); // Read stored original color
            if (originalColor) {
                // Use transition only if desired, direct attr is faster
                // cell.transition().duration(100)
                cell.attr("fill", originalColor);
            } else {
                // Fallback if original color wasn't stored somehow
                cell.style("fill", null); // Let CSS/default handle it
                console.warn(`Missing original fill for heatmap cell: cluster ${cell.attr('data-cluster')}, metric ${cell.attr('data-metric')}`);
            }
        });
    }

    function calculateEdgeWidth(processCount) {
        const count = processCount || 1;
        const minCount = 1;
        const maxCount = 100;
        const minWidth = 1;
        const maxWidth = 5;
        const range = (maxCount - minCount) || 1;
        const width = minWidth + (maxWidth - minWidth) * ((count - minCount) / range);
        return Math.max(minWidth, Math.min(width, maxWidth));
    }

    const CYTOSCAPE_STYLE = [
        { selector: 'node', style: {
            'background-color': '#888',
            'label': 'data(label)',
            'width': 'mapData(NodeWeight, 0, 1, 15, 60)',
            'height': 'mapData(NodeWeight, 0, 1, 15, 60)',
            'font-size': 10, 'color': '#000',
            'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 4,
            'border-width': 0.5,
            'border-color': '#555',
            'shape': 'ellipse',
            'transition-property': 'background-color, shape, border-color, border-width',
            'transition-duration': '0.15s'
        }},
        { selector: 'edge', style: {
            'line-color': DEFAULT_UNKNOWN_COLOR,
            'target-arrow-color': DEFAULT_UNKNOWN_COLOR,
            'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
            'transition-property': 'line-color, target-arrow-color, width, z-index',
            'transition-duration': '0.15s',
            'z-index': 1
        }},
        { selector: 'node[Classification = "Internal"]', style: {
            'shape': 'square'
        }},
        { selector: 'node[Classification = "External"]', style: {
            'shape': 'ellipse'
        }},
        {
            selector: 'node[?is_attacker]',
            style: {
                'border-color': '#FF3333',
                'border-width': 3,
                'border-style': 'solid'
            }
        }
    ];

    function generateUniqueHighlightColor() {
        const MIN_HUE_DIFF = 30;
        let attempts = 0;
        const existingHues = Array.from(clusterHighlightColors.values()).map(hslString => {
            const match = hslString.match(/hsl\((\d+),/);
            return match ? parseInt(match[1], 10) : -1;
        }).filter(h => h !== -1);

        while (attempts < 100) {
            let hue = Math.floor(Math.random() * 360);
            if ((hue >= 0 && hue <= 25) || (hue >= 335 && hue <= 360) || (hue >= 195 && hue <= 265)) {
                attempts++;
                continue;
            }
            let isDistinct = existingHues.every(existingHue => {
                let diff = Math.abs(hue - existingHue);
                return diff >= MIN_HUE_DIFF && (360 - diff) >= MIN_HUE_DIFF;
            });
            if (isDistinct) {
                const newColor = `hsl(${hue}, 85%, 60%)`;
                console.log(`Generated distinct color: ${newColor} (Hue: ${hue})`);
                return newColor;
            }
            attempts++;
        }
        console.warn("Could not find highly distinct color, using fallback random hue.");
        let fallbackHue;
        do {
            fallbackHue = Math.floor(Math.random() * 360);
        } while ((fallbackHue >= 0 && fallbackHue <= 25) || (fallbackHue >= 335 && fallbackHue <= 360) || (fallbackHue >= 195 && fallbackHue <= 265));
        return `hsl(${fallbackHue}, 85%, 60%)`;
    }

    function deselectCurrentNode() {
        if (selectedNodeId && sidebarCy) {
            const node = sidebarCy.getElementById(selectedNodeId);
            if (node && node.length > 0) {
                const originalColor = node.scratch('_originalColor');
                if (originalColor) {
                    node.style('background-color', originalColor);
                } else {
                    const clusterID = node.data('clusterID');
                    const clusterColor = clusterHighlightColors.get(clusterID) || '#888';
                    node.style('background-color', clusterColor);
                    console.warn(`Missing scratch color for node ${selectedNodeId}, reverted using cluster/default color.`);
                }
                node.connectedEdges().forEach(edge => {
                    const edgeKey = `${edge.data('source')}|${edge.data('target')}|${edge.data('Protocol')}`;
                    if (!selectedSidebarEdges.has(edgeKey)) {
                         const originalEdgeColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                         const originalEdgeWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                         edge.style({
                            'line-color': originalEdgeColor,
                            'target-arrow-color': originalEdgeColor,
                            'width': originalEdgeWidth,
                            'z-index': 1
                         });
                    }
                });
                 node.unselect();
                console.log(`Node ${selectedNodeId} and its non-selected edges deselected.`);
            } else {
                console.warn(`Attempted to deselect node ${selectedNodeId}, but it was not found.`);
            }
            selectedNodeId = null;
        }
    }

    function visualizeClusterInSidebar(clusterID, nodeColor, isAnomalous) {
        return new Promise((resolve, reject) => {
            const stringClusterID = String(clusterID);

            if (sidebarCy && sidebarCy.nodes(`[clusterID = "${stringClusterID}"]`).length > 0 && addedSidebarClusters.has(stringClusterID)) {
                console.log(`Cluster ${stringClusterID} elements already in sidebar. Re-focusing/styling.`);
                sidebarCy.nodes(`[clusterID = "${stringClusterID}"]`).forEach(node => {
                    node.style('background-color', nodeColor);
                    if (!node.scratch('_originalColor')) {
                        node.scratch('_originalColor', nodeColor);
                    }
                });
                if (selectedSidebarNodes.size === 0 && selectedSidebarEdges.size === 0) {
                    loadSidebarClusterTable(stringClusterID, 1);
                } else {
                    console.log("Selections exist, table update will be handled by selection logic if necessary.");
                }
                resolve({ clusterId: stringClusterID, status: 're-focused' });
                return;
            }

            if (addedSidebarClusters.size === 0) {
                toggleSidebar(true);
            }
            showSidebarLoading(true, false);
            sidebarInfoDiv.innerHTML = `Loading network for Cluster ${stringClusterID}...`;
            sidebarInfoDiv.style.display = 'block';

            fetch(`${API_BASE_URL}/cluster_network?cluster_id=${stringClusterID}`)
                .then(response => {
                    if (!response.ok) throw new Error(`Network error (${response.status}) for Cluster ${stringClusterID}`);
                    return response.json();
                })
                .then(data => {
                    showSidebarLoading(false, false);

                    if (!data || (!data.nodes || data.nodes.length === 0)) {
                        console.log(`No network data to display for Cluster ${stringClusterID}.`);
                        sidebarInfoDiv.innerHTML = `Cluster ${stringClusterID}: No network data.`;
                        sidebarInfoDiv.style.display = 'block';
                        addedSidebarClusters.add(stringClusterID);
                        if (selectedSidebarNodes.size === 0 && selectedSidebarEdges.size === 0) {
                            loadSidebarClusterTable(stringClusterID, 1);
                        }
                        resolve({ clusterId: stringClusterID, status: 'no-data' });
                        return;
                    }

                    const nodesToAdd = data.nodes.map(node => ({
                        group: 'nodes',
                        data: { ...node.data, clusterID: stringClusterID, Classification: node.data.Classification || 'Unknown' },
                        style: {
                            'background-color': nodeColor
                        },
                        scratch: { _originalColor: nodeColor }
                    }));

                    const edgesToAdd = data.edges.map(edge => {
                        const protocol = edge.data.Protocol || 'Unknown';
                        if (!protocolColorMap[protocol]) {
                            let randomColor;
                            do {
                                randomColor = '#' + Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0');
                            } while (randomColor.toLowerCase() === SELECTED_EDGE_COLOR.toLowerCase());
                            protocolColorMap[protocol] = randomColor;
                        }
                        const edgeColor = protocolColorMap[protocol] || DEFAULT_UNKNOWN_COLOR;
                        return {
                            group: 'edges',
                            data: { ...edge.data, clusterID: stringClusterID },
                            style: { 'line-color': edgeColor, 'target-arrow-color': edgeColor },
                            scratch: { _protocolColor: edgeColor }
                        };
                    });

                    if (!sidebarCy) {
                        sidebarCy = cytoscape({
                            container: document.getElementById('sidebar-cy'),
                            elements: { nodes: nodesToAdd, edges: edgesToAdd },
                            style: CYTOSCAPE_STYLE
                        });
                        bindSidebarGraphEvents();
                    } else {
                        sidebarCy.add(nodesToAdd.concat(edgesToAdd));
                    }

                    addedSidebarClusters.add(stringClusterID);
                    sidebarInfoDiv.style.display = 'none';

                    applySidebarSizeControls();
                    let currentLayout = document.getElementById('sidebarLayoutSelect').value;
                    if (sidebarCy.nodes(`[clusterID = "${stringClusterID}"]`).length > 0) {
                        sidebarCy.layout(sidebarLayoutOptions[currentLayout]).run();
                    }
                    
                    updateLegend(sidebarCy.edges());

                    if (selectedSidebarNodes.size === 0 && selectedSidebarEdges.size === 0) {
                        loadSidebarClusterTable(stringClusterID, 1);
                    }
                    resolve({ clusterId: stringClusterID, status: 'loaded' });
                })
                .catch(error => {
                    console.error(`Error visualizing cluster ${stringClusterID} in sidebar:`, error);
                    showSidebarLoading(false, false);
                    sidebarInfoDiv.innerHTML = `Error loading graph for Cluster ${stringClusterID}.`;
                    sidebarInfoDiv.style.display = 'block';
                    addedSidebarClusters.add(stringClusterID);
                    if (selectedSidebarNodes.size === 0 && selectedSidebarEdges.size === 0) {
                    loadSidebarClusterTable(stringClusterID, 1);
                    }
                    reject(error);
                });
        });
    }

    function updateSidebarTableForSelectedNodesAndEdges() {
        showSidebarLoading(false, true);
        sidebarTableContainer.style.display = 'none';
        sidebarTablePagination.style.display = 'none';
        sidebarSearchContainer.style.display = 'none';

        const nodesToFilterBy = Array.from(selectedSidebarNodes);
        const edgesToFilterBy = Array.from(selectedSidebarEdges).map(key => {
            const parts = key.split('|');
            return { source: parts[0], destination: parts[1], protocol: parts[2] };
        });

        if (nodesToFilterBy.length > 0) {
            console.log(`Nodes selected: ${nodesToFilterBy.join(', ')}. Loading table for their connected edges.`);
            let allConnectedEdgesData = new Set();
            let representativeEdgesForTable = [];

            nodesToFilterBy.forEach(nodeId => {
                const node = sidebarCy.getElementById(nodeId);
                if (node.length > 0) {
                    node.connectedEdges().forEach(edge => {
                        const edgeKey = `${edge.data('source')}|${edge.data('target')}|${edge.data('Protocol')}`;
                        if (!allConnectedEdgesData.has(edgeKey)) {
                            allConnectedEdgesData.add(edgeKey);
                            representativeEdgesForTable.push({
                                source: edge.data('source'),
                                destination: edge.data('target'),
                                protocol: edge.data('Protocol')
                            });
                        }
                    });
                }
            });
            if (representativeEdgesForTable.length > 0) {
                loadSidebarMultiEdgeTable(representativeEdgesForTable, 1);
            } else {
                sidebarTableContainer.innerHTML = '<p style="padding:10px; text-align:center; color:#6c757d;">Selected node(s) have no connections.</p>';
                sidebarTableContainer.style.display = 'block';
                showSidebarLoading(false, false);
            }
            sidebarInfoDiv.style.display = 'none';

        } else if (edgesToFilterBy.length > 0) {
            console.log(`Edges selected, loading multi-edge table for ${edgesToFilterBy.length} edges.`);
            loadSidebarMultiEdgeTable(edgesToFilterBy, 1);
            sidebarInfoDiv.style.display = 'none';
        } else {
            console.log("No specific nodes or edges selected. Showing table for current cluster context.");
            if (currentSidebarTableClusterId) {
                loadSidebarClusterTable(currentSidebarTableClusterId, 1);
            } else if (addedSidebarClusters.size > 0) {
                const firstClusterId = addedSidebarClusters.values().next().value;
                if (firstClusterId) loadSidebarClusterTable(firstClusterId, 1);
            } else {
                sidebarTableContainer.innerHTML = '<p id="sidebar-table-no-results" style="display: none; text-align: center; padding: 10px; color: #6c757d;">No rows match your search criteria.</p>';
                sidebarTableContainer.style.display = 'block';
                showSidebarLoading(false, false);
                sidebarInfoDiv.style.display = (!sidebarCy || sidebarCy.elements().length === 0) ? 'block' : 'none';
            }
        }
    }

    function bindSidebarGraphEvents() {
        if (!sidebarCy) return;

        sidebarCy.removeListener('mouseover');
        sidebarCy.removeListener('mouseout');
        sidebarCy.removeListener('click');
        sidebarCy.removeListener('tap');

        sidebarCy.on('mouseover', 'node, edge', (event) => {
            const el = event.target;
            const isNode = el.isNode();
            const data = el.data();
            let tooltipHTML = '';

            if (isNode) {
                let packetsIn = 0;
                let packetsOut = 0;
                el.connectedEdges().forEach(edge => {
                    const edgeData = edge.data();
                    const count = edgeData.processCount || 0;
                    if (edgeData.target === data.id) packetsIn += count;
                    if (edgeData.source === data.id) packetsOut += count;
                });
                tooltipHTML = `Node: ${data.label || data.id}<br>Class: ${data.Classification || 'N/A'}<br>Cluster: ${data.clusterID}<br>`;
                if (data.is_attacker) tooltipHTML += `<strong style="color:#FF3333;">Role: Attacker</strong><br>`;
                tooltipHTML += `Packets In: ${packetsIn}<br>Packets Out: ${packetsOut}`;
                if (data.InvolvedAttackTypes && data.InvolvedAttackTypes.length > 0) {
                    tooltipHTML += `<br><strong style="color:crimson;">Node Involved in Attacks: ${data.InvolvedAttackTypes.join(', ')}</strong>`;
                }
            } else { // Edge
                tooltipHTML = `Src: ${data.source}<br>Dst: ${data.target}<br>Proto: ${data.Protocol}<br>Count: ${data.processCount || 0}<br>Cluster: ${data.clusterID}`;
                if (data.AttackType && data.AttackType !== "N/A") {
                    tooltipHTML += `<br><strong style="color:crimson;">Edge Attack: ${data.AttackType}</strong>`;
                }
            }

            tooltip.html(tooltipHTML).style("display", "block");

            const tooltipNode = tooltip.node();
            const tooltipWidth = tooltipNode.offsetWidth;
            const tooltipHeight = tooltipNode.offsetHeight;
            const windowWidth = window.innerWidth;
            const windowHeight = window.innerHeight;
            
            let left = (event.originalEvent?.pageX ?? (event.renderedPosition?.x + (document.getElementById('sidebar-cy')?.getBoundingClientRect().left ?? 0))) + 10;
            let top = (event.originalEvent?.pageY ?? (event.renderedPosition?.y + (document.getElementById('sidebar-cy')?.getBoundingClientRect().top ?? 0))) + (isNode ? 10 : -15);
            
            if (left + tooltipWidth > windowWidth) {
                left = (event.originalEvent?.pageX ?? event.renderedPosition.x) - tooltipWidth - 10;
            }
            if (top + tooltipHeight > windowHeight) {
                top = (event.originalEvent?.pageY ?? event.renderedPosition.y) - tooltipHeight - (isNode ? -10 : 15);
            }
            if (top < 0) {
                top = 0;
            }

            tooltip.style("left", `${left}px`).style("top", `${top}px`);
        });

        sidebarCy.on('mouseout', 'node, edge', () => {
            tooltip.style("display", "none");
        });

        // --- CLICK AND TAP EVENTS (No changes needed for tooltip logic here) ---
        sidebarCy.on('click', 'node', (event) => {
            const clickedNode = event.target;
            const clickedNodeId = clickedNode.id();
            const clusterID = clickedNode.data('clusterID');

            if (event.originalEvent.shiftKey && clusterID) {
                console.log(`Shift+click on node ${clickedNodeId}. Selecting cluster ${clusterID}.`);
                const cellInDendro = d3.select(`#inlineDendrogramSvg .heatmap-cell[data-cluster_id="${clusterID}"]`);
                if (!cellInDendro.empty()) {
                    clusterHighlightColors.delete(String(clusterID));
                    cellInDendro.dispatch('click'); 
                    highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                } else {
                    console.warn(`Could not find heatmap cell for cluster ${clusterID} to simulate selection.`);
                    if (!clusterHighlightColors.has(String(clusterID))) {
                        const highlightColor = generateUniqueHighlightColor();
                        clusterHighlightColors.set(String(clusterID), highlightColor);
                        visualizeClusterInSidebar(clusterID, highlightColor, clickedNode.data('is_attacker')); // Pass node's attacker status
                        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                    } else {
                        visualizeClusterInSidebar(clusterID, clusterHighlightColors.get(String(clusterID)), clickedNode.data('is_attacker'));
                    }
                }
                loadSidebarClusterTable(clusterID, 1);
                return; 
            }

            if (selectedSidebarEdges.size > 0) {
                selectedSidebarEdges.forEach(edgeKey => {
                    const parts = edgeKey.split('|');
                    const edgeSelector = `edge[source = "${parts[0]}"][target = "${parts[1]}"][Protocol = "${parts[2]}"]`;
                    const edge = sidebarCy.elements(edgeSelector);
                    if (edge.length > 0) {
                        const originalColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                        const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                        edge.style({ 'line-color': originalColor, 'target-arrow-color': originalColor, 'width': originalWidth, 'z-index': 1 });
                        edge.unselect();
                    }
                });
                selectedSidebarEdges.clear();
            }

            if (selectedSidebarNodes.has(clickedNodeId)) {
                selectedSidebarNodes.delete(clickedNodeId);
                const originalNodeColor = clickedNode.scratch('_originalColor') || clusterHighlightColors.get(clickedNode.data('clusterID')) || '#888';
                clickedNode.style('background-color', originalNodeColor);
                clickedNode.unselect();
                console.log(`Node ${clickedNodeId} deselected.`);

                clickedNode.connectedEdges().forEach(edge => {
                    const sourceId = edge.source().id();
                    const targetId = edge.target().id();
                    let otherNodeIsSelected = false;

                    if (sourceId === clickedNodeId && selectedSidebarNodes.has(targetId)) {
                        otherNodeIsSelected = true;
                    } else if (targetId === clickedNodeId && selectedSidebarNodes.has(sourceId)) {
                        otherNodeIsSelected = true;
                    }

                    if (otherNodeIsSelected) {
                        const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                        edge.style({
                            'line-color': SELECTED_EDGE_COLOR,
                            'target-arrow-color': SELECTED_EDGE_COLOR,
                            'width': originalWidth,
                            'z-index': SELECTED_EDGE_ZINDEX
                        });
                    } else {
                        const edgeKey = `${edge.data('source')}|${edge.data('target')}|${edge.data('Protocol')}`;
                        if (!selectedSidebarEdges.has(edgeKey)) {
                            const originalEdgeColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                            const originalEdgeWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                            edge.style({
                                'line-color': originalEdgeColor,
                                'target-arrow-color': originalEdgeColor,
                                'width': originalEdgeWidth,
                                'z-index': 1
                            });
                        }
                    }
                });

            } else {
                selectedSidebarNodes.add(clickedNodeId);
                if (!clickedNode.scratch('_originalColor')) {
                    clickedNode.scratch('_originalColor', clickedNode.style('background-color'));
                }
                clickedNode.style('background-color', SELECTED_NODE_COLOR);
                clickedNode.select();
                console.log(`Node ${clickedNodeId} selected.`);

                clickedNode.connectedEdges().forEach(edge => {
                    if (!edge.scratch('_originalWidth')) {
                        edge.scratch('_originalWidth', edge.style('width'));
                    }
                    if (!edge.scratch('_protocolColor')) {
                        edge.scratch('_protocolColor', edge.style('line-color'));
                    }
                    const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                    edge.style({
                        'line-color': SELECTED_EDGE_COLOR,
                        'target-arrow-color': SELECTED_EDGE_COLOR,
                        'width': originalWidth,
                        'z-index': SELECTED_EDGE_ZINDEX
                    });
                });
            }
            updateSidebarTableForSelectedNodesAndEdges();
            sidebarInfoDiv.style.display = 'none';
        });

        sidebarCy.on('click', 'edge', (event) => {
            const edge = event.target;
            const source = edge.data('source');
            const target = edge.data('target');
            const protocol = edge.data('Protocol');
            const edgeKey = `${source}|${target}|${protocol}`;
            const clusterID = edge.data('clusterID'); 

            if (event.originalEvent.shiftKey && clusterID) {
                console.log(`Shift+click on edge ${edgeKey}. Selecting cluster ${clusterID}.`);
                const cellInDendro = d3.select(`#inlineDendrogramSvg .heatmap-cell[data-cluster_id="${clusterID}"]`);
                if (!cellInDendro.empty()) {
                    clusterHighlightColors.delete(String(clusterID));
                    cellInDendro.dispatch('click');
                    highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                } else {
                    console.warn(`Could not find heatmap cell for cluster ${clusterID} to simulate selection.`);
                    if (!clusterHighlightColors.has(String(clusterID))) {
                        const highlightColor = generateUniqueHighlightColor();
                        clusterHighlightColors.set(String(clusterID), highlightColor);
                        visualizeClusterInSidebar(clusterID, highlightColor, false);
                        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                    } else {
                        visualizeClusterInSidebar(clusterID, clusterHighlightColors.get(String(clusterID)), false);
                    }
                }
                loadSidebarClusterTable(clusterID, 1);
                return; 
            }

            if (selectedSidebarNodes.size > 0) {
                selectedSidebarNodes.forEach(nodeId => {
                    const node = sidebarCy.getElementById(nodeId);
                    if (node.length > 0) {
                        const originalNodeColor = node.scratch('_originalColor') || clusterHighlightColors.get(node.data('clusterID')) || '#888';
                        node.style('background-color', originalNodeColor);
                        node.unselect();
                        node.connectedEdges().forEach(connEdge => {
                            const connEdgeKey = `${connEdge.data('source')}|${connEdge.data('target')}|${connEdge.data('Protocol')}`;
                            if (!selectedSidebarEdges.has(connEdgeKey) && connEdgeKey !== edgeKey) {
                                const originalEdgeColor = connEdge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                                const originalEdgeWidth = connEdge.scratch('_originalWidth') || calculateEdgeWidth(connEdge.data('processCount'));
                                connEdge.style({
                                    'line-color': originalEdgeColor,
                                    'target-arrow-color': originalEdgeColor,
                                    'width': originalEdgeWidth,
                                    'z-index': 1
                                });
                            }
                        });
                    }
                });
                selectedSidebarNodes.clear();
            }

            if (selectedSidebarEdges.has(edgeKey)) {
                selectedSidebarEdges.delete(edgeKey);
                const originalColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                edge.style({ 'line-color': originalColor, 'target-arrow-color': originalColor, 'width': originalWidth, 'z-index': 1 });
                edge.unselect();
            } else {
                selectedSidebarEdges.add(edgeKey);
                const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                edge.style({
                    'line-color': SELECTED_EDGE_COLOR,
                    'target-arrow-color': SELECTED_EDGE_COLOR,
                    'width': originalWidth, 
                    'z-index': SELECTED_EDGE_ZINDEX
                });
                edge.select();
            }
            updateSidebarTableForSelectedNodesAndEdges();
        });

        sidebarCy.on('tap', function(event){
            if (event.target === sidebarCy) {
                let deselectedSomething = false;

                if (selectedSidebarNodes.size > 0) {
                    selectedSidebarNodes.forEach(nodeId => {
                        const node = sidebarCy.getElementById(nodeId);
                        if (node.length > 0) {
                            const originalColor = node.scratch('_originalColor') || clusterHighlightColors.get(node.data('clusterID')) || '#888';
                            node.style('background-color', originalColor);
                            node.unselect();
                            node.connectedEdges().forEach(edge => {
                                const edgeKey = `${edge.data('source')}|${edge.data('target')}|${edge.data('Protocol')}`;
                                if (!selectedSidebarEdges.has(edgeKey)) {
                                    const originalEdgeColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                                    const originalEdgeWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                                    edge.style({
                                        'line-color': originalEdgeColor,
                                        'target-arrow-color': originalEdgeColor,
                                        'width': originalEdgeWidth,
                                        'z-index': 1
                                    });
                                }
                            });
                        }
                    });
                    selectedSidebarNodes.clear();
                    deselectedSomething = true;
                    console.log("Node selections cleared by tapping sidebar background.");
                }

                if (selectedSidebarEdges.size > 0) {
                    selectedSidebarEdges.forEach(edgeKey => {
                        const parts = edgeKey.split('|');
                        const edgeSelector = `edge[source = "${parts[0]}"][target = "${parts[1]}"][Protocol = "${parts[2]}"]`;
                        const edge = sidebarCy.elements(edgeSelector);
                        if (edge.length > 0) {
                            const originalColor = edge.scratch('_protocolColor') || DEFAULT_UNKNOWN_COLOR;
                            const originalWidth = edge.scratch('_originalWidth') || calculateEdgeWidth(edge.data('processCount'));
                            edge.style({ 'line-color': originalColor, 'target-arrow-color': originalColor, 'width': originalWidth, 'z-index': 1 });
                            edge.unselect();
                        }
                    });
                    selectedSidebarEdges.clear();
                    deselectedSomething = true;
                    console.log("Edge selections cleared by tapping sidebar background.");
                }

                if (deselectedSomething) {
                    updateSidebarTableForSelectedNodesAndEdges();
                }
                sidebarInfoDiv.style.display = (!sidebarCy || sidebarCy.elements().length === 0) ? 'block' : 'none';
            }
        });
    }

    function applySidebarSizeControls() {
        if (!sidebarCy || sidebarCy.elements().length === 0) {
            console.log("Sidebar graph not ready or empty, skipping size update.");
            return;
        }

        // Read min/max inputs according to new requirements
        const minNS_input = parseFloat(document.getElementById('sidebarNodeSizeMin').value) || 2;
        const maxNS_input_val = document.getElementById('sidebarNodeSizeMax').value;
        const maxNS_input = maxNS_input_val ? parseFloat(maxNS_input_val) : Infinity;

        // Edge width logic remains the same.
        const minEW_input = Math.max(parseFloat(document.getElementById('sidebarEdgeWidthMin').value) || 1, 0.1);
        const maxEW_input = Math.max(parseFloat(document.getElementById('sidebarEdgeWidthMax').value) || 8, minEW_input + 0.1);

        sidebarCy.batch(() => {
            const nodes = sidebarCy.nodes();
            if (nodes.length > 0) {
                const allDiameters = []; // Array to store calculated diameters

                nodes.forEach(n => {
                    const packetCount = n.data('packetCount') || 0;
                    // 1. Calculate size based on square root of packet count.
                    let diameter = Math.sqrt(packetCount);

                    // 2. Apply minimum size constraint.
                    diameter = Math.max(minNS_input, diameter);

                    // 3. Apply maximum size constraint ONLY if user provided a finite number.
                    if (isFinite(maxNS_input)) {
                        diameter = Math.min(diameter, maxNS_input);
                    }
                    
                    allDiameters.push(diameter); // Store the final diameter for this node

                    const styleToApply = {
                        'width': diameter,
                        'height': diameter
                    };

                    // Check if the node is an attacker and set proportional border width
                    if (n.data('is_attacker')) {
                        const borderWidth = Math.max(2, Math.min(diameter * 0.1, 10));
                        styleToApply['border-width'] = borderWidth;
                    }

                    // Avoid overriding styles of actively selected nodes
                    if (!selectedSidebarNodes.has(n.id())) {
                        n.style(styleToApply);
                    }
                });
                
                // --- NEW: Update the placeholder for the max node size input ---
                if (allDiameters.length > 0) {
                    const currentMaxNodeSize = Math.max(...allDiameters);
                    const maxNodeSizeInput = document.getElementById('sidebarNodeSizeMax');
                    if (maxNodeSizeInput) {
                        // Update the placeholder with the calculated max, formatted to 2 decimal places.
                        maxNodeSizeInput.placeholder = currentMaxNodeSize.toFixed(2);
                    }
                }
            }

            // --- Edge Width Logic (Unchanged) ---
            const edges = sidebarCy.edges();
            if (edges.length > 0) {
                const edgeCounts = edges.map(e => e.data('processCount') || 1);
                const actualMinCount = Math.max(1, Math.min(...edgeCounts));
                const actualMaxCount = Math.max(actualMinCount, Math.max(...edgeCounts));
                const countRange = (actualMaxCount - actualMinCount);

                edges.forEach(e => {
                    const count = e.data('processCount') || 1;
                    let normalizedCount = 0;
                    if (countRange > 0) {
                        const clampedCount = Math.max(actualMinCount, Math.min(count, actualMaxCount));
                        normalizedCount = (clampedCount - actualMinCount) / countRange;
                    } else if (edges.length > 0) {
                        normalizedCount = 0;
                    }
                    let width = minEW_input + normalizedCount * (maxEW_input - minEW_input);
                    width = Math.max(minEW_input, Math.min(width, maxEW_input));

                    e.scratch('_originalWidth', width);
                    
                    const edgeKey = `${e.data('source')}|${e.data('target')}|${e.data('Protocol')}`;
                    const edgeIsSelected = selectedSidebarEdges.has(edgeKey);

                    if (!edgeIsSelected) {
                        e.style('width', width);
                    } else {
                        e.style('width', SELECTED_EDGE_WIDTH);
                    }
                });
            }
        }); 
    }

    function updateSidebarTableForSelectedEdges() {
        // --- Handle Node Selection First ---
        if (selectedNodeId && sidebarCy) {
            const node = sidebarCy.getElementById(selectedNodeId);
            if (node && node.length > 0) {
                const connectedEdgeData = node.connectedEdges().map(edge => ({
                    source: edge.data('source'),
                    destination: edge.data('target'),
                    protocol: edge.data('Protocol')
                }));
                 if (connectedEdgeData.length > 0) {
                    console.log(`Node ${selectedNodeId} selected, loading its multi-edge table.`);
                    loadSidebarMultiEdgeTable(connectedEdgeData, 1);
                 } else {
                    console.log(`Node ${selectedNodeId} selected, but has no connections.`);
                    sidebarTableContainer.innerHTML = '<p id="sidebar-table-no-results" style="display: none; text-align: center; padding: 10px; color: #6c757d;">No rows match your search criteria.</p><p style="padding:10px; text-align:center; color:#6c757d;">Selected node has no connections.</p>';
                    sidebarTableContainer.style.display = 'block';
                    sidebarTablePagination.style.display = 'none';
                    sidebarSearchContainer.style.display = 'none'; // Hide search for empty table
                 }
                 sidebarInfoDiv.style.display = 'none'; // Hide default info
                 return; // Exit function after handling node selection
            } else {
                 // Node ID was selected but node not found (maybe removed), reset selection
                 console.warn(`Selected node ${selectedNodeId} not found, resetting selection state.`);
                 selectedNodeId = null; // Resetting here, deselectCurrentNode might have been called already
            }
        }

        if (selectedSidebarEdges.size > 0) {
            const edgeList = Array.from(selectedSidebarEdges).map(key => {
                const parts = key.split('|');
                return { source: parts[0], destination: parts[1], protocol: parts[2] };
            });
            console.log(`Edges selected, loading multi-edge table for ${edgeList.length} edges.`);
            loadSidebarMultiEdgeTable(edgeList, 1);
            sidebarInfoDiv.style.display = 'none'; // Hide default info
        }
        else {
            console.log("No node or edge selected. Checking for remaining added clusters...");
            if (addedSidebarClusters.size > 0) {
                // If clusters remain in the sidebar, show table for the first one
                const firstRemainingClusterId = addedSidebarClusters.values().next().value;
                console.log(`Loading table for first remaining cluster: ${firstRemainingClusterId}`);
                loadSidebarClusterTable(firstRemainingClusterId, 1);
                sidebarInfoDiv.style.display = 'none'; // Hide default info if showing cluster table
            } else {
                // If no clusters remain, clear table and show default info message
                console.log("No clusters remain in the sidebar. Clearing table and showing info message.");
                sidebarTableContainer.innerHTML = '<p id="sidebar-table-no-results" style="display: none; text-align: center; padding: 10px; color: #6c757d;">No rows match your search criteria.</p>'; // Clear table content
                sidebarTableContainer.style.display = 'none'; // Hide table container
                sidebarTablePagination.style.display = 'none'; // Hide pagination
                sidebarSearchContainer.style.display = 'none'; // Hide search
                sidebarInfoDiv.innerHTML = 'Click a cell on the heatmap to add its cluster. Click nodes or edges in the graph to highlight and filter the table below.'; // Default message
                sidebarInfoDiv.style.display = 'block'; // Show info message
                currentSidebarTableClusterId = null; // Ensure no stale cluster ID remains
                sidebarTableMode = 'cluster'; // Reset mode
            }
        }
    }

    function loadSidebarMultiEdgeTable(edgeList, page, searchQuery = "") {
        if (!edgeList || edgeList.length === 0) {
            updateSidebarTableForSelectedEdges();
            return;
        }
        sidebarTableMode = 'edges';
        showSidebarLoading(false, true);
        sidebarTableContainer.style.display = 'none';
        sidebarSearchContainer.style.display = 'block';

        const payload = {
            edges: edgeList,
            page: page,
            page_size: TABLE_PAGE_SIZE,
            search: searchQuery
        };

        fetch(`${API_BASE_URL}/get_multi_edge_table`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(response => response.ok ? response.json() : Promise.reject(`Failed multi-edge table page (${response.status})`))
        .then(data => {
            showSidebarLoading(false, false);
            _renderSidebarTable(data, page);
            sidebarTableContainer.scrollTop = 0;
        })
        .catch(error => {
            console.error("Error fetching multi-edge sidebar table:", error);
            showSidebarLoading(false, false);
            sidebarTableContainer.innerHTML = `<p style="color: red; padding: 10px;">Error loading table data for selected edges.</p>`;
            sidebarTableContainer.style.display = 'block';
        });
    }

    function applyAllHeatmapHighlights() {
        d3.selectAll('rect.cell').each(function() {
            const cell = d3.select(this);
            const originalColor = cell.attr("data-original-fill");
            if (originalColor) { cell.attr("fill", originalColor); }
        });
        clusterHighlightColors.forEach((color, clusterId) => {
            d3.selectAll('rect.cell[data-cluster="' + clusterId + '"]').attr('fill', color);
        });
    }

    function showLoading() {
        globalAbortController = new AbortController();
        document.getElementById('loading-overlay').style.display = 'flex';
        const cancelBtn = document.getElementById('cancelLoadingBtn');
        if (cancelBtn) {
            cancelBtn.disabled = false;
        }
    }
    function hideLoading() { document.getElementById('loading-overlay').style.display = 'none'; }

    function updateLegend(cyEdges = null) {
        const legendTitleElement = document.getElementById('protocol-legend-title'); // Get the specific title element
        const legendTableBody = d3.select('#legend tbody');

        let protocols = new Set();
        let calculationPromise;
        let totalCount = 0;

        if (cyEdges && cyEdges.length > 0) {
            // Sidebar Mode: Calculate percentages locally
            if (legendTitleElement) legendTitleElement.textContent = "Sidebar Protocols";
            const counts = {};
            cyEdges.forEach(edge => {
                const protocol = (edge.data('Protocol') || 'Unknown').trim();
                if (!protocol) return;
                protocols.add(protocol);
                const count = edge.data('processCount') || 1;
                counts[protocol] = (counts[protocol] || 0) + count;
                totalCount += count;
            });
            totalCount = totalCount || 1; // Avoid division by zero
            const percentages = {};
            Object.entries(counts).forEach(([p, c]) => { percentages[p] = (c / totalCount) * 100; });
            calculationPromise = Promise.resolve(percentages); // Resolve immediately
        } else {
            // Global Mode: Fetch percentages from backend
            if (legendTitleElement) legendTitleElement.textContent = "Protocol Legend"; // Default title
            calculationPromise = fetch(`${API_BASE_URL}/protocol_percentages`)
                .then(res => {
                    if (!res.ok) { // Check if response is not OK
                        // Try to parse JSON error, otherwise use status text
                        return res.json().catch(() => ({ error: `Failed global percentages. Status: ${res.status}` })).then(err => {
                            // If it's an object with an error key, use that, otherwise create one.
                            throw new Error(err.error || `Failed global percentages. Status: ${res.statusText || res.status}`);
                        });
                    }
                    return res.json();
                })
                .catch(error => {
                    console.error("Error fetching global protocol percentages:", error.message || error);
                    // Ensure legend title is set even on error
                    if (legendTitleElement) legendTitleElement.textContent = "Protocol Legend (Error)";
                    return {}; // Return empty object on error to prevent further issues
                });
        }

        // Common logic after getting percentages
        calculationPromise.then(percentages => {
            legendTableBody.html(''); // Clear the table *just before* adding new rows

            if (!cyEdges || cyEdges.length === 0) { // Only if in global mode and percentages might define protocols
                Object.keys(percentages).forEach(proto => { if(proto) protocols.add(proto); });
            }

            protocols.forEach(proto => {
                if (proto && !protocolColorMap[proto]) {
                    let randomColor;
                    do {
                        randomColor = '#' + Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0');
                    } while (randomColor.toLowerCase() === SELECTED_EDGE_COLOR.toLowerCase());
                    protocolColorMap[proto] = randomColor;
                }
            });
            if (!protocolColorMap['Unknown']) {
                protocolColorMap['Unknown'] = DEFAULT_UNKNOWN_COLOR;
            }

            const sortedProtocols = Array.from(protocols).filter(p => p).sort((a, b) => (percentages[b] || 0) - (percentages[a] || 0));

            sortedProtocols.forEach(protocol => {
                const pct = percentages[protocol] || 0;
                const pctText = (pct > 0.01 ? pct.toFixed(2) : (pct > 0 ? '<0.01' : '0.00')) + '%';
                const color = protocolColorMap[protocol] || DEFAULT_UNKNOWN_COLOR;
                legendTableBody.append('tr').html(
                    `<td>${protocol}</td><td><span class="color-box" style="background-color:${color}"></span></td><td>${pctText}</td>`
                );
            });

            if (sidebarCy) {
                sidebarCy.edges().forEach(edge => {
                    const protocol = edge.data('Protocol') || 'Unknown';
                    const newColor = protocolColorMap[protocol] || DEFAULT_UNKNOWN_COLOR;
                    const edgeKey = `${edge.data('source')}|${edge.data('target')}|${edge.data('Protocol')}`;
                    // Check if any connected node is the currently selected single node
                    const sourceNodeSelected = selectedNodeId && edge.source().id() === selectedNodeId;
                    const targetNodeSelected = selectedNodeId && edge.target().id() === selectedNodeId;
                    const edgeIsSelected = selectedSidebarEdges.has(edgeKey);

                    if (!sourceNodeSelected && !targetNodeSelected && !edgeIsSelected) {
                        edge.style({'line-color': newColor, 'target-arrow-color': newColor});
                    }
                    edge.scratch('_protocolColor', newColor);
                });
            }
        }).catch(error => { // Catch errors from the calculationPromise itself
            console.error("Error processing percentages for legend:", error);
            if (legendTitleElement) legendTitleElement.textContent = "Protocol Legend (Data Error)";
            legendTableBody.html('<tr><td colspan="3" style="text-align:center;color:red;">Could not load protocol data.</td></tr>');
        });
    }

    function updateHeatmap() {
        return new Promise((resolve, reject) => {
            window.fullHeatmapData = {};
            window.heatmapSortOrders = {};
            window.heatmapCountSortOrder = [];

            const filterParamsBase = {
                payloadKeyword: document.getElementById('payloadSearch').value.trim().toLowerCase(),
                sourceFilter: document.getElementById('sourceFilter').value.trim().toLowerCase(),
                destinationFilter: document.getElementById('destinationFilter').value.trim().toLowerCase(),
                protocolFilter: document.getElementById('protocolFilter').value.trim().toLowerCase(),
                minSourceAmt: document.getElementById('minSourceAmtFilter').value,
                maxSourceAmt: document.getElementById('maxSourceAmtFilter').value,
                minDestinationAmt: document.getElementById('minDestinationAmtFilter').value,
                maxDestinationAmt: document.getElementById('maxDestinationAmtFilter').value
            };

            if (window.lastAppliedTimeSelection && window.lastAppliedTimeSelection.startTime) {
                filterParamsBase.start_time = window.lastAppliedTimeSelection.startTime.toISOString();
                filterParamsBase.end_time = window.lastAppliedTimeSelection.endTime.toISOString();
                console.log(`updateHeatmap: Using lastAppliedTimeSelection for filtering: ${filterParamsBase.start_time} to ${filterParamsBase.end_time}`);
            } else {
                console.warn("updateHeatmap: lastAppliedTimeSelection is not set. Heatmap may show data for the entire file.");
            }

            Promise.all(metrics.map(m => {
                const filterParams = { ...filterParamsBase, metric: m.value };

                return fetch(`${API_BASE_URL}/filter_and_aggregate`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(filterParams),
                        signal: globalAbortController.signal
                    })
                    .then(response => {
                        if (!response.ok) throw new Error('Network response was not ok');
                        return response.json();
                    })
                    .then(data => ({ metric: m.label, pivotData: data }))
                    .catch(error => {
                        if (error.name === 'AbortError') console.log(`Heatmap fetch aborted for ${m.label}.`);
                        else console.error(`Error fetching heatmap for ${m.label}:`, error);
                        return { metric: m.label, pivotData: [], error: true };
                    });
            }))
            .then(results => {
                const validResults = results.filter(r => !r.error);
                validResults.forEach(r => {
                    window.fullHeatmapData[r.metric] = r.pivotData;
                });
                resolve(validResults);
            })
            .catch(error => reject(error));
        });
    }

    function updateRowOrderSelectState() {
        const dendrogramSortSelect = document.getElementById('dendrogramSortMetricSelect');
        const rowOrderSelect = document.getElementById('rowOrderSelect');
        const rowOrderLabel = document.querySelector('label[for="rowOrderSelect"]');

        if (!dendrogramSortSelect || !rowOrderSelect || !rowOrderLabel) {
            console.warn("Could not find all elements for updating rowOrderSelect state.");
            return;
        }

        if (dendrogramSortSelect.value === 'Default') {
            rowOrderSelect.disabled = true;
            rowOrderSelect.style.opacity = '0.5';
            rowOrderSelect.style.pointerEvents = 'none';
            rowOrderLabel.style.opacity = '0.5';
        } else {
            rowOrderSelect.disabled = false;
            rowOrderSelect.style.opacity = '';
            rowOrderSelect.style.pointerEvents = '';
            rowOrderLabel.style.opacity = '';
        }
    }

    function loadSidebarClusterTable(clusterID, page, searchQuery = "") {
        if (!clusterID) return;
        sidebarTableMode = 'cluster';
        currentSidebarTableClusterId = clusterID;
        showSidebarLoading(false, true);
        sidebarTableContainer.style.display = 'none';
        sidebarSearchContainer.style.display = 'block';

        const searchParam = searchQuery ? `&search=${encodeURIComponent(searchQuery)}` : "";
        const url = `${API_BASE_URL}/get_cluster_table?cluster_id=${clusterID}&page=${page}&page_size=${TABLE_PAGE_SIZE}${searchParam}`;

        fetch(url)
            .then(response => response.ok ? response.json() : Promise.reject(`Failed to fetch cluster table (${response.status})`))
            .then(data => {
                showSidebarLoading(false, false);
                _renderSidebarTable(data, page);
                sidebarTableContainer.scrollTop = 0;
            })
            .catch(error => {
                console.error("Error fetching sidebar cluster table:", error);
                showSidebarLoading(false, false);
                sidebarTableContainer.innerHTML = `<p style="color: red; padding: 10px;">Error loading table data.</p>`;
                sidebarTableContainer.style.display = 'block';
            });
    }

    sidebarGoPageBtn.addEventListener('click', function () {
        let pageInput = document.getElementById('sidebarCurrentPageInput');
        let page = parseInt(pageInput.value, 10);
        const totalPagesStr = document.getElementById('sidebarTotalPages').textContent;
        const totalPages = totalPagesStr === '?' ? Infinity : parseInt(totalPagesStr, 10);
        const searchQuery = document.getElementById('sidebarTableSearchInput').value || "";

        if (!isNaN(page) && page >= 1 && (page <= totalPages || totalPages === Infinity)) {
            if (sidebarTableMode === 'cluster' && currentSidebarTableClusterId) {
                loadSidebarClusterTable(currentSidebarTableClusterId, page, searchQuery);
            } else if (sidebarTableMode === 'edges') {
                let edgeList = [];
                if (selectedSidebarNodes.size > 0 && sidebarCy) {
                    selectedSidebarNodes.forEach(nodeId => {
                        const node = sidebarCy.getElementById(nodeId);
                        if (node && node.length > 0) {
                           node.connectedEdges().forEach(edge => {
                                edgeList.push({ source: edge.data('source'), destination: edge.data('target'), protocol: edge.data('Protocol') });
                           });
                        }
                    });
                    edgeList = Array.from(new Set(edgeList.map(JSON.stringify)), JSON.parse);
                } else if (selectedSidebarEdges.size > 0) {
                   edgeList = Array.from(selectedSidebarEdges).map(key => {
                       const parts = key.split('|');
                       return { source: parts[0], destination: parts[1], protocol: parts[2] };
                   });
                }
                if (edgeList.length > 0) {
                    loadSidebarMultiEdgeTable(edgeList, page, searchQuery);
                }
            }
        } else {
            alert(`Please enter a valid page number between 1 and ${totalPagesStr}.`);
        }
    });

    function loadClusterTablePage(clusterID, page) {
        currentClusterID = clusterID;
        fetch(`${API_BASE_URL}/get_cluster_table?cluster_id=${clusterID}&page=${page}&page_size=${TABLE_PAGE_SIZE}`)
            .then(response => response.ok ? response.text() : Promise.reject(`Failed main table page (${response.status})`))
            .then(html => {
                const container = document.getElementById('table-container');
                container.innerHTML = html;
                container.style.display = 'block';
                document.getElementById('table-pagination').style.display = 'block';

                const summaryElem = container.querySelector('#table-summary');
                if (summaryElem && summaryElem.dataset.total) {
                    const total = parseInt(summaryElem.dataset.total, 10);
                    const totalPages = Math.ceil(total / TABLE_PAGE_SIZE);
                    document.getElementById('totalPages').textContent = totalPages || 1;
                    document.getElementById('currentPageInput').value = page;
                    document.getElementById('currentPageInput').max = totalPages || 1;
                } else {
                    document.getElementById('totalPages').textContent = '?';
                    document.getElementById('currentPageInput').value = page;
                    console.warn("No table summary total in main table response.");
                }
                container.scrollTop = 0;
            }).catch(error => {
                console.error("Error fetching main cluster table:", error);
                document.getElementById('table-container').innerHTML = `<p style="color: red; padding: 10px;">Error loading table data.</p>`;
                document.getElementById('table-container').style.display = 'block';
                document.getElementById('table-pagination').style.display = 'none';
            });
       }

    function createClusterTable(clusterID) {
        loadClusterTablePage(clusterID, 1);
        document.getElementById('table-search-container').style.display = "block";
       }

    function visualizeNetwork(elements) {
        if (globalCy) { globalCy.destroy(); }
        globalCy = cytoscape({
            container: document.getElementById('cy'),
            elements: elements,
            style: CYTOSCAPE_STYLE,
            layout: { name: 'cose' }
        });
        applySizeControls();
       }

    function applySizeControls() {
        if (!globalCy) return;
        const minNS = Math.max(parseFloat(document.getElementById('nodeSizeMin').value) || 15, 1);
        const maxNS = Math.max(parseFloat(document.getElementById('nodeSizeMax').value) || 60, minNS + 1);
        const minEW = Math.max(parseFloat(document.getElementById('edgeWidthMin').value) || 1, 0.1);
        const maxEW = Math.max(parseFloat(document.getElementById('edgeWidthMax').value) || 10, minEW + 0.1);

        globalCy.batch(() => {
            globalCy.nodes().forEach(n => {
                const weight = n.data('NodeWeight') ?? 0.5;
                let size = minNS + (maxNS - minNS) * weight;
                size = Math.max(minNS, Math.min(size, maxNS));
                n.style({ 'width': size, 'height': size });
            });
            const counts = globalCy.edges().map(e => e.data('processCount') || 1);
            if (counts.length > 0) {
                const minCount = Math.min(...counts);
                const maxCount = Math.max(...counts);
                const countRange = (maxCount - minCount) || 1;

                globalCy.edges().forEach(e => {
                    const count = e.data('processCount') || 1;
                    let width = minEW + (maxEW - minEW) * ((count - minCount) / countRange);
                    width = Math.max(minEW, Math.min(width, maxEW));
                    e.style('width', width);
                });
            }
        });
       }

    function applyEdgeFilter() {
        if (!globalCy) return;
        const sourceFilter = document.getElementById('edgeFilterSource').value.toLowerCase();
        const destFilter = document.getElementById('edgeFilterDestination').value.toLowerCase();
        const protoFilter = document.getElementById('edgeFilterProtocol').value.toLowerCase();
        const weightFilterStr = document.getElementById('edgeFilterWeight').value;
        const countFilterStr = document.getElementById('edgeFilterProcessCount').value;

        const parseFilter = (filterStr) => {
            const match = filterStr.match(/^([<>=!]+)?\s*(\d+(\.\d+)?)$/);
            if (match) {
                const operator = match[1] || '==';
                const value = parseFloat(match[2]);
                return { operator, value };
            }
            return null;
        };
        const weightFilter = parseFilter(weightFilterStr);
        const countFilter = parseFilter(countFilterStr);

        globalCy.edges().forEach(edge => {
            let show = true;
            const data = edge.data();

            if (sourceFilter && !data.source?.toLowerCase().includes(sourceFilter)) show = false;
            if (destFilter && !data.target?.toLowerCase().includes(destFilter)) show = false;
            if (protoFilter && !data.Protocol?.toLowerCase().includes(protoFilter)) show = false;

            if (weightFilter && show) {
                const edgeWeight = data.EdgeWeight || 0;
                switch (weightFilter.operator) {
                    case '>=': if (!(edgeWeight >= weightFilter.value)) show = false; break;
                    case '>':  if (!(edgeWeight > weightFilter.value)) show = false; break;
                    case '<=': if (!(edgeWeight <= weightFilter.value)) show = false; break;
                    case '<':  if (!(edgeWeight < weightFilter.value)) show = false; break;
                    case '==': if (!(edgeWeight == weightFilter.value)) show = false; break;
                    case '!=': if (!(edgeWeight != weightFilter.value)) show = false; break;
                }
            }

            if (countFilter && show) {
                const processCount = data.processCount || 0;
                 switch (countFilter.operator) {
                    case '>=': if (!(processCount >= countFilter.value)) show = false; break;
                    case '>':  if (!(processCount > countFilter.value)) show = false; break;
                    case '<=': if (!(processCount <= countFilter.value)) show = false; break;
                    case '<':  if (!(processCount < countFilter.value)) show = false; break;
                    case '==': if (!(processCount == countFilter.value)) show = false; break;
                    case '!=': if (!(processCount != countFilter.value)) show = false; break;
                }
            }
            edge.style('display', show ? 'element' : 'none');
        });
       }

    function clearEdgeFilter() {
        document.getElementById('edgeFilterSource').value = '';
        document.getElementById('edgeFilterDestination').value = '';
        document.getElementById('edgeFilterProtocol').value = '';
        document.getElementById('edgeFilterWeight').value = '';
        document.getElementById('edgeFilterProcessCount').value = '';
        if(globalCy) { globalCy.edges().style('display', 'element'); }
       }

    function toggleSidebarFullscreen() {
        if (!document.fullscreenEnabled) {
            alert("Fullscreen mode is not supported by your browser.");
            return;
        }

        if (!document.fullscreenElement && !isSidebarFullscreen) {
            // Enter fullscreen
            sidebar.requestFullscreen().then(() => {
                // NEW: Move tooltip inside the sidebar to ensure it's in the same rendering layer
                if (tooltip && sidebar) {
                    sidebar.appendChild(tooltip.node());
                }

                sidebar.classList.add('fullscreen');
                legendContainer.classList.add('fullscreen-active');
                document.body.classList.add('sidebar-fullscreen');
                isSidebarFullscreen = true;
                sidebarFullscreenBtn.innerHTML = '&#x274C;';
                sidebarFullscreenBtn.title = "Exit Sidebar Fullscreen";
                console.log("Entered sidebar fullscreen.");
                if (sidebarCy) {
                    setTimeout(() => {
                        sidebarCy.resize();
                        sidebarCy.fit(null, 50);
                    }, 100);
                }
            }).catch(err => {
                alert(`Error attempting to enable fullscreen mode: ${err.message} (${err.name})`);
                console.error("Fullscreen request failed:", err);
            });
        } else if (document.fullscreenElement === sidebar || isSidebarFullscreen) {
            // Exit fullscreen
            document.exitFullscreen().catch(err => {
                alert(`Error attempting to disable fullscreen mode: ${err.message} (${err.name})`);
                console.error("Fullscreen exit failed:", err);
                // Ensure cleanup is called even on error
                cleanupFullscreenStyles();
            });
        } else {
            console.warn("Fullscreen state mismatch detected.");
            cleanupFullscreenStyles();
        }
    }

    function cleanupFullscreenStyles() {
        // NEW: Move tooltip back to the body so it works in normal mode
        if (tooltip && document.body) {
            document.body.appendChild(tooltip.node());
        }

        sidebar.classList.remove('fullscreen');
        legendContainer.classList.remove('fullscreen-active');
        document.body.classList.remove('sidebar-fullscreen');
        isSidebarFullscreen = false;
        sidebarFullscreenBtn.innerHTML = '&#x2922;';
        sidebarFullscreenBtn.title = "Toggle Sidebar Fullscreen";
        console.log("Cleaned up fullscreen styles.");
        // This call is important to restore the non-fullscreen layout correctly
        toggleSidebar(isSidebarOpen);
    }

    document.addEventListener('DOMContentLoaded', async () => {
        // --- Magnifying Glass Variables (Correct Placement) ---
        const body = document.body;
        let magnifyingGlass, magnifyingContent, bodyClone;
        let isMagnifyingGlassActive = false;
        const zoomFactor = 2; // How much to zoom in

        // --- Get all other elements ---
        tooltip = d3.select("#tooltip");
        const fileInput = document.getElementById('fileInput');
        const loadDemoBtn = document.getElementById('loadDemoBtn');
        const applyFiltersBtn = document.getElementById('applyFiltersBtn');
        const sidebarToggleBtn = document.getElementById('sidebar-toggle');
        const resetSidebarBtn = document.getElementById('resetSidebarBtn');
        const sidebarTableContainer = document.getElementById('sidebar-table-container');
        const sidebarGoPageBtn = document.getElementById('sidebarGoPageBtn');
        const sidebarSearchInput = document.getElementById('sidebarTableSearchInput');
        const sidebarFullscreenBtn = document.getElementById('sidebarFullscreenBtn');
        const sidebarNodeSizeMin = document.getElementById('sidebarNodeSizeMin');
        const sidebarNodeSizeMax = document.getElementById('sidebarNodeSizeMax');
        const sidebarEdgeWidthMin = document.getElementById('sidebarEdgeWidthMin');
        const sidebarEdgeWidthMax = document.getElementById('sidebarEdgeWidthMax');
        const metricSelect = document.getElementById('dendrogramSortMetricSelect');
        const thresholdSlider = document.getElementById('thresholdSlider');
        const thresholdValueSpan = document.getElementById('thresholdValue');
        const sidebarLayoutSelect = document.getElementById('sidebarLayoutSelect');
        const applyThresholdBtn = document.getElementById('applyThresholdBtn');
        const reorderTreeCheckbox = document.getElementById('reorderTreeCheckbox');
        const resetGroupingBtn = document.getElementById('resetGroupingBtn');
        const acknowledgeBtn = document.getElementById('acknowledgeNewClustersBtn');
        const messageDivForAcknowledge = document.getElementById('reclusterMessage');
        const saveSelectionBtn = document.getElementById('saveSelectionBtn');
        const cancelLoadingBtn = document.getElementById('cancelLoadingBtn');
        const showSankeyBtn = document.getElementById('showSankeyBtn');
        const sankeyCard = document.getElementById('sankeyCard');
        const showPacketSimilarityBtn = document.getElementById('showPacketSimilarityBtn');
        const refreshIpGraphBtn = document.getElementById('refreshIpGraphBtn');
        const applySankeyToHeatmapBtn = document.getElementById('applySankeyToHeatmapBtn');
        const revertSankeyFilterBtn = document.getElementById('revertSankeyFilterBtn');
        const createSubtreeBtn = document.getElementById('createSubtreeBtn');
        const backToMainTreeBtn = document.getElementById('backToMainTreeBtn');
        const processTimelineSelectionBtn = document.getElementById('processTimelineSelectionBtn');
        const csvProcessTimeDiv = document.getElementById('csvProcessTime');
        const toggleTimelineBtn = document.getElementById('toggleTimelineBtn');
        const manualStartTimeInput = document.getElementById('manualStartTime');
        const manualEndTimeInput = document.getElementById('manualEndTime');
        const applyManualTimeBtn = document.getElementById('applyManualTimeBtn');
        const applyGranularityBtn = document.getElementById('applyGranularityBtn');

        if (applyGranularityBtn) {
            applyGranularityBtn.addEventListener('click', () => {
                // Invalidate the cache to force a refetch with the new granularity
                window.fullTimelineData = null;
                drawTimeline();
            });
        }

        createMagnifyingGlass();
        const magnifyingGlassBtn = document.getElementById('magnifyingGlassBtn');
        if (magnifyingGlassBtn) {
            // Pass the click event to the toggle function
            magnifyingGlassBtn.addEventListener('click', (e) => toggleMagnifyingGlass(e));
        }

        document.getElementById('dendrogramCard').style.display = 'none';
        document.getElementById('packetSimilarityCard').style.display = 'none';
        document.getElementById('sankeyCard').style.display = 'none';
        document.getElementById('timeline-card').style.display = 'none';
        if (csvProcessTimeDiv) csvProcessTimeDiv.style.display = 'none';
        renderSavedItemsList();

        if (manualStartTimeInput && manualEndTimeInput) {
            manualStartTimeInput.addEventListener('input', updateManualTimeButtonState);
            manualEndTimeInput.addEventListener('input', updateManualTimeButtonState);
        }

        if (toggleTimelineBtn) {
            toggleTimelineBtn.addEventListener('click', function() {
                const timelineCard = document.getElementById('timeline-card');
                if (!timelineCard) return;

                const isHidden = timelineCard.style.display === 'none' || !timelineCard.style.display;
                if (isHidden) {
                    timelineCard.style.display = 'block';
                    this.textContent = 'Hide Timeline';
                    drawTimeline();
                } else {
                    timelineCard.style.display = 'none';
                    this.textContent = 'Show Timeline';
                }
            });
        }

        if (processTimelineSelectionBtn) {
            processTimelineSelectionBtn.addEventListener('click', async () => {
                if (!window.currentTimeSelection) {
                    alert("Please select a time range on the timeline first.");
                    return;
                }
                
                await initializeAndLoadVisuals(
                    window.currentTimeSelection.startTime.toISOString(),
                    window.currentTimeSelection.endTime.toISOString()
                );
            });
        }

        if (loadDemoBtn) {
            loadDemoBtn.addEventListener('click', async () => {
                const localProcessingTimeDiv = document.getElementById('csvProcessTime');
                if (localProcessingTimeDiv) localProcessingTimeDiv.style.display = 'none';

                showLoading();

                try {
                    const processResponse = await fetch(`${API_BASE_URL}/load_demo_file`, {
                        method: 'POST',
                        signal: globalAbortController.signal
                    });

                    if (globalAbortController.signal.aborted) throw new DOMException("Aborted");
                    if (!processResponse.ok) {
                        const errText = await processResponse.text();
                        throw new Error(`Demo file loading failed: ${errText}`);
                    }
                    
                    const responseData = await processResponse.json();
                    await handleSuccessfulFileLoad(responseData);

                } catch (error) {
                    if (error.name !== 'AbortError') {
                        alert(`Error loading demo file: ${error.message}`);
                        document.getElementById('timeline-card').style.display = 'none';
                    }
                } finally {
                    hideLoading();
                }
            });
        }

        if (fileInput) {
            fileInput.addEventListener('change', async function(event) {
                const file = event.target.files[0];
                const localProcessingTimeDiv = document.getElementById('csvProcessTime');
                if (localProcessingTimeDiv) localProcessingTimeDiv.style.display = 'none';

                if (file) {
                    if (!file.name.toLowerCase().endsWith('.parquet')) {
                        alert("Invalid file type. Please select a .parquet file.");
                        event.target.value = null;
                        return;
                    }
                    
                    showLoading();
                    const formData = new FormData();
                    formData.append('file', file);

                    try {
                        const processResponse = await fetch(`${API_BASE_URL}/process_uploaded_file`, {
                            method: 'POST',
                            body: formData,
                            signal: globalAbortController.signal
                        });

                        if (globalAbortController.signal.aborted) throw new DOMException("Aborted");
                        if (!processResponse.ok) {
                            const errText = await processResponse.text();
                            throw new Error(`File processing failed: ${errText}`);
                        }
                        
                        const responseData = await processResponse.json();
                        await handleSuccessfulFileLoad(responseData);

                    } catch (error) {
                        if (error.name !== 'AbortError') {
                            alert(`Error loading file: ${error.message}`);
                            document.getElementById('timeline-card').style.display = 'none';
                        }
                    } finally {
                        hideLoading();
                        if (event.target) event.target.value = null;
                    }
                }
            });
        }

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', async () => {
                showLoading();
                try {
                    window.activeSankeyNodeFilter = null;
                    window.sankeyMatchingClusterIds.clear();
                    if (applySankeyToHeatmapBtn) {
                        applySankeyToHeatmapBtn.disabled = true;
                    }
                    if (revertSankeyFilterBtn) {
                        revertSankeyFilterBtn.disabled = true;
                    }
                    await updateHeatmap();
                    if (globalAbortController.signal.aborted) throw new DOMException("Operation aborted by user.", "AbortError");
                    if (window.heatmapCountSortOrder && window.heatmapCountSortOrder.length > 0) {
                        window.allClusterIdsMasterList = [...new Set(window.heatmapCountSortOrder.map(String))];
                    } else {
                        if (window.fullHeatmapData && window.fullHeatmapData['Count']) {
                            window.allClusterIdsMasterList = window.fullHeatmapData['Count'].map(d => String(d.cluster));
                        } else {
                            window.allClusterIdsMasterList = [];
                        }
                    }
                    await updateTimeInfoDisplay();
                    if (globalAbortController.signal.aborted) throw new DOMException("Operation aborted by user.", "AbortError");
                    await loadInlineDendrogram();
                    if (globalAbortController.signal.aborted) throw new DOMException("Operation aborted by user.", "AbortError");
                    highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                    const localThresholdSlider = document.getElementById('thresholdSlider');
                    if (localThresholdSlider && window.lastTreeRoot) {
                        requestAnimationFrame(() => {
                            localThresholdSlider.dispatchEvent(new Event('input'));
                        });
                    }
                } catch (error) {
                    if (error.name === 'AbortError') {
                        console.log("Filter application aborted by user.");
                    } else {
                        alert(`Error applying filters: ${error.message || 'Unknown error'}`);
                    }
                } finally {
                    if (!globalAbortController.signal.aborted) hideLoading();
                }
            });
        }
        if (sidebarToggleBtn) {
            sidebarToggleBtn.addEventListener('click', () => toggleSidebar());
        }
        if (resetSidebarBtn) {
            resetSidebarBtn.addEventListener('click', () => {
                console.log("Performing FAST client-side reset.");
                clearSidebarVisualization();
                updateLegend();
                if (window.activeSankeyNodeFilter) {
                    window.activeSankeyNodeFilter = null;
                    window.sankeyMatchingClusterIds.clear();
                    const applyBtn = document.getElementById('applySankeyToHeatmapBtn');
                    const revertBtn = document.getElementById('revertSankeyFilterBtn');
                    if (applyBtn) applyBtn.disabled = true;
                    if (revertBtn) revertBtn.disabled = true;
                    console.log("Sankey filter state cleared on client-side.");
                }
                resetHeatmapHighlights();
                selectedNodeId = null;
                document.getElementById('sidebarLayoutSelect').value = 'cose';
            });
        }
        if (sidebarFullscreenBtn) {
            sidebarFullscreenBtn.addEventListener('click', toggleSidebarFullscreen);
        }
        if (saveSelectionBtn) {
            saveSelectionBtn.addEventListener('click', handleSaveSelection);
        }
        if (sidebarTableContainer) {
            sidebarTableContainer.addEventListener('click', handleSidebarTableRowClick);
        }
        if (sidebarSearchInput) {
            sidebarSearchInput.addEventListener('input', filterSidebarTable);
        }
        if (sidebarGoPageBtn) {
            sidebarGoPageBtn.addEventListener('click', function() {
                let pageInput = document.getElementById('sidebarCurrentPageInput');
                let page = parseInt(pageInput.value, 10);
                const totalPagesStr = document.getElementById('sidebarTotalPages').textContent;
                const totalPages = totalPagesStr === '?' ? Infinity : parseInt(totalPagesStr, 10);
                const searchQuery = document.getElementById('sidebarTableSearchInput').value || "";

                if (!isNaN(page) && page >= 1 && (page <= totalPages || totalPages === Infinity)) {
                    if (sidebarTableMode === 'cluster' && currentSidebarTableClusterId) {
                        loadSidebarClusterTable(currentSidebarTableClusterId, page, searchQuery);
                    } else if (sidebarTableMode === 'edges') {
                        let edgeList = [];
                        if (selectedSidebarNodes.size > 0 && sidebarCy) {
                            selectedSidebarNodes.forEach(nodeId => {
                                const node = sidebarCy.getElementById(nodeId);
                                if (node && node.length > 0) {
                                node.connectedEdges().forEach(edge => {
                                        edgeList.push({ source: edge.data('source'), destination: edge.data('target'), protocol: edge.data('Protocol') });
                                });
                                }
                            });
                            edgeList = Array.from(new Set(edgeList.map(JSON.stringify)), JSON.parse);
                        } else if (selectedSidebarEdges.size > 0) {
                        edgeList = Array.from(selectedSidebarEdges).map(key => {
                            const parts = key.split('|');
                            return { source: parts[0], destination: parts[1], protocol: parts[2] };
                        });
                        }
                        if (edgeList.length > 0) {
                            loadSidebarMultiEdgeTable(edgeList, page, searchQuery);
                        }
                    }
                } else {
                    alert(`Please enter a valid page number between 1 and ${totalPagesStr}.`);
                }
            });
        }
        if (sidebarLayoutSelect) {
            sidebarLayoutSelect.addEventListener('change', applySidebarLayout);
        }
        if (sidebarNodeSizeMin) sidebarNodeSizeMin.addEventListener('input', applySidebarSizeControls);
        if (sidebarNodeSizeMax) sidebarNodeSizeMax.addEventListener('input', applySidebarSizeControls);
        if (sidebarEdgeWidthMin) sidebarEdgeWidthMin.addEventListener('input', applySidebarSizeControls);
        if (sidebarEdgeWidthMax) sidebarEdgeWidthMax.addEventListener('input', applySidebarSizeControls);
        if (metricSelect) {
            metricSelect.addEventListener('change', () => {
                updateRowOrderSelectState();
                if (window.lastTreeData) {
                    showLoading();
                    try {
                        showInlineDendrogram(window.lastTreeData, document.getElementById("inline-dendrogram-container").clientHeight, currentNewClusterIds);
                        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                        const localThresholdSlider = document.getElementById('thresholdSlider');
                        requestAnimationFrame(() => {
                            if (localThresholdSlider && window.lastTreeRoot) localThresholdSlider.dispatchEvent(new Event('input'));
                        });
                    } catch (error) {
                        if (error.name !== 'AbortError') console.error("Error reloading dendrogram on metric change:", error);
                    } finally {
                        if (!globalAbortController.signal.aborted) hideLoading();
                    }
                }
            });
        }
        const rowOrderSelect = document.getElementById("rowOrderSelect");
        if (rowOrderSelect && metricSelect) {
            rowOrderSelect.addEventListener('change', () => {
                if (metricSelect.value !== 'Default' && window.lastTreeData) {
                    showLoading();
                    try {
                        showInlineDendrogram(window.lastTreeData, document.getElementById("inline-dendrogram-container").clientHeight, currentNewClusterIds);
                        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                        const localThresholdSlider = document.getElementById('thresholdSlider');
                        requestAnimationFrame(() => {
                            if (localThresholdSlider && window.lastTreeRoot) localThresholdSlider.dispatchEvent(new Event('input'));
                        });
                    } catch (error) {
                        if (error.name !== 'AbortError') console.error("Error reloading dendrogram on row order change:", error);
                    } finally {
                        if (!globalAbortController.signal.aborted) hideLoading();
                    }
                }
            });
        }
        if (reorderTreeCheckbox) {
            reorderTreeCheckbox.addEventListener('change', () => {
                if (window.lastTreeData) {
                    showLoading();
                    try {
                        showInlineDendrogram(window.lastTreeData, document.getElementById("inline-dendrogram-container").clientHeight, currentNewClusterIds);
                        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                        const localThresholdSlider = document.getElementById('thresholdSlider');
                        requestAnimationFrame(() => {
                            if (localThresholdSlider && window.lastTreeRoot) localThresholdSlider.dispatchEvent(new Event('input'));
                        });
                    } catch (error) {
                        if (error.name !== 'AbortError') console.error("Error reloading dendrogram on reorder checkbox change:", error);
                    } finally {
                        if (!globalAbortController.signal.aborted) hideLoading();
                    }
                }
            });
        }
        if (thresholdSlider && thresholdValueSpan) {
            thresholdSlider.addEventListener('input', function() {
                const physicalValue = parseInt(this.value, 10);
                const currentMaxDistForDisplay = window.lastAppliedThreshold || 100;
                const scaledPercentage = Math.round((physicalValue / 100) * currentMaxDistForDisplay);
                thresholdValueSpan.textContent = `${scaledPercentage}%`;
                const svgContent = d3.select("#inlineDendrogramSvg g");
                const thresholdBar = d3.select("#threshold-bar");
                if (!window.lastTreeRoot || svgContent.empty() || thresholdBar.empty()) {
                    if (thresholdBar && !thresholdBar.empty()) thresholdBar.style("display", "none");
                    return;
                }
                const layoutHeight = window.currentD3LayoutHeight;
                const currentD3MarginTop = (typeof margin !== 'undefined' && margin.top) ? margin.top : 30;
                if (layoutHeight && layoutHeight > 0) {
                    const thresholdY_untransformed = layoutHeight * (physicalValue / 100) + currentD3MarginTop;
                    const currentTransform = d3.zoomTransform(d3.select("#inlineDendrogramSvg").node());
                    const transformedY = currentTransform.applyY(thresholdY_untransformed);
                    const currentD3MarginLeft = (typeof margin !== 'undefined' && margin.left) ? margin.left : 30;
                    const currentD3MarginRight = (typeof margin !== 'undefined' && margin.right) ? margin.right : 30;
                    thresholdBar.attr("x1", currentTransform.applyX(0)).attr("x2", currentTransform.applyX((window.currentLayoutWidth || 0) + currentD3MarginLeft + currentD3MarginRight)).attr("y1", transformedY).attr("y2", transformedY).style("display", "block");
                } else {
                    thresholdBar.style("display", "none");
                }
            });
        }
        if (applyThresholdBtn) {
            applyThresholdBtn.addEventListener('click', applyThresholdGrouping);
        }
        if (resetGroupingBtn) {
            resetGroupingBtn.addEventListener('click', resetGroupingAndRedraw);
        }
        const mainGoPageBtn = document.getElementById('goPageBtn');
        if (mainGoPageBtn) {
            mainGoPageBtn.addEventListener('click', function() {
                let pageInput = document.getElementById('currentPageInput');
                let page = parseInt(pageInput.value, 10);
                const totalPagesStr = document.getElementById('totalPages').textContent;
                const totalPages = totalPagesStr === '?' ? Infinity : parseInt(totalPagesStr, 10);
                if (!isNaN(page) && page >= 1 && (page <= totalPages || totalPages === Infinity) && currentClusterID) {
                    loadClusterTablePage(currentClusterID, page);
                } else {
                    alert(`Please enter a valid page number between 1 and ${totalPagesStr}.`);
                }
            });
        }
        const mainTableSearchInput = document.getElementById('tableSearchInput');
        if (mainTableSearchInput) {
            mainTableSearchInput.addEventListener('input', function() {
                console.log("Main table search not active for this view (placeholder).");
            });
        }
        if (acknowledgeBtn && messageDivForAcknowledge) {
            acknowledgeBtn.addEventListener('click', () => {
                messageDivForAcknowledge.textContent = '';
                acknowledgeBtn.style.display = 'none';
                currentNewClusterIds.clear();
                if (window.lastTreeData) {
                    showInlineDendrogram(window.lastTreeData, document.getElementById("inline-dendrogram-container").clientHeight, currentNewClusterIds);
                }
            });
        }
        if (showPacketSimilarityBtn) {
            showPacketSimilarityBtn.addEventListener('click', function() {
                const card = document.getElementById('packetSimilarityCard');
                if (!card) return;
                if (card.style.display === 'none' || card.style.display === '') {
                    const dataLoadedCheck = window.originalTreeData && Object.keys(window.originalTreeData).length > 0 && !window.originalTreeData.error;
                    if (!dataLoadedCheck) {
                        alert("Please upload data first.");
                        return;
                    }
                    card.style.display = 'block';
                    this.textContent = 'Hide IP Community Graph';
                    fetchAndRenderLouvainIpGraph();
                } else {
                    card.style.display = 'none';
                    this.textContent = 'Show Community IP Graph';
                    if (window.louvainIpCy) {
                        window.louvainIpCy.destroy();
                        window.louvainIpCy = null;
                    }
                }
            });
        }
        if (refreshIpGraphBtn) {
            refreshIpGraphBtn.addEventListener('click', fetchAndRenderLouvainIpGraph);
        }
        if (showSankeyBtn) {
            showSankeyBtn.addEventListener('click', function() {
                if (!sankeyCard) {
                    return;
                }
                if (sankeyCard.style.display === 'none' || sankeyCard.style.display === '') {
                    const dataLoadedCheckSankey = window.originalTreeData && Object.keys(window.originalTreeData).length > 0 && !window.originalTreeData.error;
                    if (!dataLoadedCheckSankey) {
                        alert("Please upload and process a file first to generate data for the Sankey diagram.");
                        return;
                    }
                    sankeyCard.style.display = 'block';
                    this.textContent = 'Hide Sankey Diagram';
                    fetchAndRenderSankeyDiagram();
                } else {
                    sankeyCard.style.display = 'none';
                    this.textContent = 'Show Sankey Diagram';
                    window.activeSankeyNodeFilter = null;
                    window.sankeyMatchingClusterIds.clear();
                    if (applySankeyToHeatmapBtn) {
                        applySankeyToHeatmapBtn.disabled = true;
                    }
                    if (revertSankeyFilterBtn) {
                        revertSankeyFilterBtn.disabled = true;
                    }
                    if (window.lastTreeData) {
                        loadInlineDendrogram();
                    }
                }
            });
        }
        if (applySankeyToHeatmapBtn) {
            applySankeyToHeatmapBtn.addEventListener('click', () => {
                if (window.activeSankeyNodeFilter) {
                    updateMainViewAfterSankeyFilter().then(() => {
                        if (revertSankeyFilterBtn) {
                            revertSankeyFilterBtn.disabled = false;
                        }
                    });
                } else {
                    alert("No Sankey node selected to apply as filter.");
                }
            });
        }
        if (revertSankeyFilterBtn) {
            revertSankeyFilterBtn.addEventListener('click', async () => {
                showLoading();
                try {
                    window.activeSankeyNodeFilter = null;
                    window.sankeyMatchingClusterIds.clear();
                    await loadInlineDendrogram();
                    revertSankeyFilterBtn.disabled = true;
                    if (applySankeyToHeatmapBtn) {
                        applySankeyToHeatmapBtn.disabled = true;
                        applySankeyToHeatmapBtn.style.backgroundColor = "#6c757d";
                    }
                    const sankeySVG = d3.select("#sankey-diagram-container svg");
                    if (!sankeySVG.empty()) {
                        sankeySVG.dispatch('click');
                    }
                } catch (error) {
                    console.error("Error during Sankey filter revert:", error);
                    alert("An error occurred while reverting the filter.");
                } finally {
                    hideLoading();
                }
            });
        }
        if (createSubtreeBtn) createSubtreeBtn.addEventListener('click', handleCreateSubtree);
        if (backToMainTreeBtn) backToMainTreeBtn.addEventListener('click', handleBackToMainTree);
        if (cancelLoadingBtn) {
            cancelLoadingBtn.addEventListener('click', () => {
                if (globalAbortController) {
                    globalAbortController.abort();
                }
                hideLoading();
                const reclusterMessageDiv = document.getElementById('reclusterMessage');
                if (reclusterMessageDiv) {
                    reclusterMessageDiv.textContent = "Operation cancelled by user.";
                    reclusterMessageDiv.style.color = "#757575";
                }
                if (cancelLoadingBtn) cancelLoadingBtn.disabled = true;
            });
        }

        if (applyManualTimeBtn) {
            applyManualTimeBtn.addEventListener('click', () => {
                if (!window.timelineXScale || !window.timelineBrush) {
                    alert("The timeline chart is not active. Please load data first.");
                    return;
                }
        
                const startTimeValue = manualStartTimeInput.value;
                const endTimeValue = manualEndTimeInput.value;
        
                if (!startTimeValue || !endTimeValue) {
                    alert("Please enter both a start and end time.");
                    return;
                }
        
                const startTime = new Date(startTimeValue);
                const endTime = new Date(endTimeValue);
        
                if (isNaN(startTime.getTime()) || isNaN(endTime.getTime())) {
                    alert("Invalid date format. Please use the format 'YYYY-MM-DD HH:MM:SS'.");
                    return;
                }
        
                if (endTime <= startTime) {
                    alert("End time must be after the start time.");
                    return;
                }

                const [domainStart, domainEnd] = window.timelineXScale.domain();
                if (startTime < domainStart || endTime > domainEnd) {
                    alert("The entered times are outside the range of the loaded data.\nPlease select a time between " + formatDateTimeForInput(domainStart) + " and " + formatDateTimeForInput(domainEnd));
                    
                    if (window.lastAppliedTimeSelection) {
                        updateManualTimeInputs(window.lastAppliedTimeSelection.startTime, window.lastAppliedTimeSelection.endTime);
                    } else {
                        updateManualTimeInputs(domainStart, domainend);
                    }
                    disableManualApplyButton();
                    return;
                }
        
                const startPixel = window.timelineXScale(startTime);
                const endPixel = window.timelineXScale(endTime);
        
                const brushGroup = d3.select("#timeline-container .brush");
                if (!brushGroup.empty() && window.timelineBrush) {
                    brushGroup.call(window.timelineBrush.move, [startPixel, endPixel]);
                } else {
                    console.error("Could not find the timeline brush element to update.");
                }
            });
        }

        document.addEventListener('fullscreenchange', () => {
            if (!document.fullscreenElement && isSidebarFullscreen) {
                cleanupFullscreenStyles();
                if (sidebarCy) {
                    setTimeout(() => {
                        sidebarCy.resize();
                        sidebarCy.fit(null, 50);
                    }, 400);
                }
            } else if (document.fullscreenElement === sidebar && !isSidebarFullscreen) {
                isSidebarFullscreen = true;
                sidebar.classList.add('fullscreen');
                legendContainer.classList.add('fullscreen-active');
                document.body.classList.add('sidebar-fullscreen');
                sidebarFullscreenBtn.innerHTML = '&#x274C;';
                sidebarFullscreenBtn.title = "Exit Sidebar Fullscreen";
                if (sidebarCy) {
                    setTimeout(() => {
                        sidebarCy.resize();
                        sidebarCy.fit(null, 50);
                    }, 100);
                }
            }
        });

        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                const timelineCard = document.getElementById('timeline-card');
                if (timelineCard && timelineCard.style.display !== 'none') {
                    console.log('Debounced resize event: Redrawing timeline.');
                    drawTimeline();
                }
            }, 250);
        });

        populateSankeyDimensionCheckboxes();
    });

    function showInlineDendrogram(data, svgH = 400, newClusterIds = new Set()) {
        const containerDiv = document.getElementById("inline-dendrogram-container");
        const dendrogramCard = document.getElementById('dendrogramCard');
        const treeControls = document.getElementById('treeControls');
        const reorderCheckbox = document.getElementById('reorderTreeCheckbox');
        const svg = d3.select("#inlineDendrogramSvg");

        const metaDataLineDiv = document.getElementById('dendrogramMetaDataLine');

        svg.selectAll("*").remove();
        if (metaDataLineDiv) metaDataLineDiv.innerHTML = '';

        svg.append("line").attr("id", "threshold-bar")
            .attr("stroke", "rgba(220, 53, 69, 0.7)")
            .attr("stroke-width", 2)
            .attr("stroke-dasharray", "5 3")
            .style("pointer-events", "none")
            .style("display", "none");

        const highlightStrokeWidth = 1.5;
        const defaultStrokeColor = '#fff';
        const defaultStrokeWidth = 0.2;
        const anomalyOverrideColor = "orange";
        const minBlueIntensity = 0.05;
        const customBluesInterpolator = t_val => d3.interpolateBlues(minBlueIntensity + Math.max(0, Math.min(1, t_val)) * (1 - minBlueIntensity));
        const minGreenIntensity = 0.15;
        const customGreensInterpolator = t_val => d3.interpolateGreens(minGreenIntensity + Math.max(0, Math.min(1, t_val)) * (1 - minGreenIntensity));

        const blueColorScales = {};
        const greenColorScales = {};

        if (!containerDiv || !dendrogramCard || !treeControls || !reorderCheckbox || !svg.node()) {
            if (dendrogramCard) dendrogramCard.style.display = 'block';
            if (containerDiv) containerDiv.style.height = `${svgH}px`;
            svg.append("text").attr("x", "50%").attr("y", "50%").attr("text-anchor", "middle").attr("dominant-baseline", "central")
                .text("Error: Cannot calculate layout - missing elements.");
            if (treeControls) treeControls.style.display = "none";
            if (metaDataLineDiv) metaDataLineDiv.innerHTML = 'Error displaying metadata.';
            window.lastTreeRoot = null;
            window.lastTreeData = null;
            return;
        }

        dendrogramCard.style.display = 'block';

        let calculatedHeight = svgH;
        if (typeof svgH !== 'number' || svgH < 200) {
            try {
                const viewportHeight = window.innerHeight;
                const cardRect = dendrogramCard.getBoundingClientRect();
                const cardTopOffset = cardRect.top;
                const cardStyle = window.getComputedStyle(dendrogramCard);
                const cardMarginBottom = parseFloat(cardStyle.marginBottom) || 0;
                const cardPaddingTop = parseFloat(cardStyle.paddingTop) || 0;
                const cardPaddingBottom = parseFloat(cardStyle.paddingBottom) || 0;
                const controlsHeight = treeControls.offsetHeight || 50;
                const estimatedTopSectionHeight = document.querySelector('#dendrogramCard .dendro-header')?.offsetHeight || 70;
                const containerStyle = window.getComputedStyle(containerDiv);
                const containerMarginBottom = parseFloat(containerStyle.marginBottom) || 10;
                const safetyMargin = 30;
                const spaceBelowCardTop = viewportHeight - cardTopOffset - cardMarginBottom - safetyMargin;
                const availableHeight = spaceBelowCardTop - cardPaddingTop - estimatedTopSectionHeight - containerMarginBottom - controlsHeight - cardPaddingBottom;
                calculatedHeight = Math.max(250, Math.min(availableHeight, viewportHeight * 0.75));
            } catch (e) {
                calculatedHeight = 400;
            }
        }
        window.currentDendrogramHeight = calculatedHeight;
        svgH = calculatedHeight;
        containerDiv.style.height = `${svgH}px`;

        if (!data || data.id === undefined || data.is_minimal === true || (data.children && data.children.length === 0 && data.id && data.cluster_id) || data.no_tree || data.error) {
            let message = "No hierarchical data available or error loading.";
            let metaPartsForEmpty = [];
            let clusterInfoText = '0 Clusters';
            let packetInfoText = "Packets: N/A";

            if (data && data.is_minimal === true) {
                message = `Tree cannot be built: Only one cluster (${data.cluster_id || 'N/A'}) found.`;
                clusterInfoText = `1 Cluster (${data.cluster_id || 'N/A'})`;
                if (window.fullHeatmapData && window.fullHeatmapData['Count'] && data.cluster_id) {
                    const singleClusterEntry = window.fullHeatmapData['Count'].find(entry => String(entry.cluster) === String(data.cluster_id));
                    if (singleClusterEntry && typeof singleClusterEntry.value === 'number') {
                        packetInfoText = `Packets: ${singleClusterEntry.value.toLocaleString()}`;
                    }
                }
            } else if (data && data.error) {
                message = `Error loading tree data: ${data.error}`;
            } else if (data && data.id && (!data.children || data.children.length === 0) && data.cluster_id) {
                message = `Tree cannot be built: Only one cluster (${data.cluster_id}) found.`;
                clusterInfoText = `1 Cluster (${data.cluster_id})`;
                if (window.fullHeatmapData && window.fullHeatmapData['Count'] && data.cluster_id) {
                    const singleClusterEntry = window.fullHeatmapData['Count'].find(entry => String(entry.cluster) === String(data.cluster_id));
                    if (singleClusterEntry && typeof singleClusterEntry.value === 'number') {
                        packetInfoText = `Packets: ${singleClusterEntry.value.toLocaleString()}`;
                    }
                }
            }

            metaPartsForEmpty.push(clusterInfoText);
            
            if (window.lastAppliedTimeSelection && window.lastAppliedTimeSelection.startTime && window.lastAppliedTimeSelection.endTime) {
                const { startTime, endTime } = window.lastAppliedTimeSelection;
                const durationSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
                const timeFormat = d3.timeFormat("%Y-%m-%d %H:%M:%S");
                metaPartsForEmpty.push(`Start: ${timeFormat(startTime)}`);
                metaPartsForEmpty.push(`End: ${timeFormat(endTime)}`);
                metaPartsForEmpty.push(`Duration: ${formatDuration(durationSeconds)}`);
            } else {
                metaPartsForEmpty.push("Start: N/A");
                metaPartsForEmpty.push("End: N/A");
                metaPartsForEmpty.push("Duration: N/A");
            }
            
            metaPartsForEmpty.push(packetInfoText);

            svg.append("text").attr("x", "50%").attr("y", "50%").attr("text-anchor", "middle").attr("dominant-baseline", "central").style("font-size", "16px").style("fill", "#555").text(message);
            if (treeControls) treeControls.style.display = "none";

            if (metaDataLineDiv) {
                const separator = "&nbsp;&nbsp;|&nbsp;&nbsp;";
                metaDataLineDiv.innerHTML = metaPartsForEmpty.filter(p => p).join(separator);
            }
            window.lastTreeRoot = null;
            window.lastTreeData = null;
            return;
        }

        const internalTopMargin = 15;
        const internalBottomMargin = 20;
        const dendrogramHeightInternal = Math.max(150, svgH - internalTopMargin - internalBottomMargin);
        const height = dendrogramHeightInternal;
        window.currentD3LayoutHeight = height;

        const features = (typeof metrics !== 'undefined' && Array.isArray(metrics)) ? metrics.map(m => m.label) : [];
        const numHeatmapFeatures = features.length;
        const heatmapRowHeight = 15;
        const heatmapSpacing = 5;

        const featureScale = d3.scaleBand().domain(features).paddingInner(0.1);
        const heatmapContentStartY = height + heatmapSpacing + margin.top;
        const approximateHeatmapContentHeight = numHeatmapFeatures * heatmapRowHeight;
        featureScale.range([heatmapContentStartY, heatmapContentStartY + approximateHeatmapContentHeight]);
        const finalHeatmapBlockHeight = (numHeatmapFeatures > 0) ? (featureScale.step() * numHeatmapFeatures) : 0;
        const heatmapStartY = height + heatmapSpacing + margin.top;
        const heatmapEndY = heatmapStartY + finalHeatmapBlockHeight - (numHeatmapFeatures > 0 ? featureScale.paddingInner() * featureScale.step() : 0);

        const root = d3.hierarchy(data);
        const currentLeaves = root.leaves();
        const leafCount = currentLeaves.length;

        const treeLayout = d3.cluster().size([1, height]);
        treeLayout(root);

        root.each(node => {
            node.structuralY = node.y;
            if (typeof node.structuralY !== 'number' || !isFinite(node.structuralY)) {
                node.structuralY = (node.parent && typeof node.parent.structuralY === 'number' && isFinite(node.parent.structuralY)) ? node.parent.structuralY : 0;
            }
            node.finalY = node.structuralY;
        });

        const structuralLeaves = [...currentLeaves].sort((a, b) => a.x - b.x);
        const structuralClusterOrGroupIds = structuralLeaves.map(leaf => leaf.data?.cluster_id).filter(id => id !== undefined && id !== null).map(String);
        const minLeafSpacingStructural = 20;
        const requiredWidthStructural = structuralClusterOrGroupIds.length * minLeafSpacingStructural;
        const containerWidth = containerDiv.clientWidth || 600;
        const widthAvailableInContainer = Math.max(300, containerWidth - margin.left - margin.right);
        const structuralLayoutWidth = Math.max(requiredWidthStructural, widthAvailableInContainer);
        const structuralXScale = d3.scaleBand().domain(structuralClusterOrGroupIds).range([margin.left, margin.left + structuralLayoutWidth]).paddingInner(0);

        root.eachAfter(node => {
            if (node.children && node.children.length > 0) {
                const validChildrenX = node.children.map(c => c.structuralX).filter(x => typeof x === 'number' && isFinite(x) && x >= 0);
                if (validChildrenX.length > 0) {
                    node.structuralX = d3.mean(validChildrenX);
                } else {
                    node.structuralX = (structuralLayoutWidth / 2 + margin.left);
                }
            } else {
                const id = node.data?.cluster_id;
                if (id !== undefined && id !== null) {
                    const bandStart = structuralXScale(String(id));
                    if (bandStart !== undefined && typeof bandStart === 'number') {
                        node.structuralX = bandStart + structuralXScale.bandwidth() / 2;
                    } else {
                        node.structuralX = -1000;
                    }
                } else {
                    node.structuralX = -1000;
                }
            }
            if (typeof node.structuralX !== 'number' || !isFinite(node.structuralX)) {
                node.structuralX = (structuralLayoutWidth / 2 + margin.left);
            }
        });

        let metricSortedLeaves = [...currentLeaves];
        const metricSelectElem = document.getElementById('dendrogramSortMetricSelect');
        const selectedMetric = metricSelectElem ? metricSelectElem.value : 'Default';

        const aggregatedLeafData = new Map();
        const aggregateOriginalClusters = (originalIds, isGroupNode) => {
            const aggregatedMetrics = {};
            const countMetricStore = window.fullHeatmapData['Count'] || []; 
            const isSingleOriginalCluster = originalIds.length === 1 && !isGroupNode;

            let definitiveClusterAnomaly = 'normal';
            originalIds.forEach(originalId => {
                const countEntry = countMetricStore.find(entry => String(entry.cluster) === String(originalId));
                if (countEntry && countEntry.clusterAnomaly === 'anomaly') {
                    definitiveClusterAnomaly = 'anomaly';
                }
            });

            features.forEach(metricLabel => {
                const metricStore = window.fullHeatmapData[metricLabel] || [];
                let valuesForAggregation = [];

                originalIds.forEach(originalId => {
                    const originalEntry = metricStore.find(entry => String(entry.cluster) === String(originalId));
                    if (originalEntry) {
                        const value = originalEntry.value;
                        const countEntryForWeight = countMetricStore.find(entry => String(entry.cluster) === String(originalId));
                        const weight = countEntryForWeight?.value || 1;

                        if (value !== null && typeof value !== 'undefined' && isFinite(value)) {
                            valuesForAggregation.push({ value, weight });
                        }
                    }
                });
                
                aggregatedMetrics[`${metricLabel}_anomaly`] = definitiveClusterAnomaly;
                let finalValue = null;

                if (valuesForAggregation.length > 0) {
                    if (isSingleOriginalCluster) {
                        finalValue = valuesForAggregation[0].value;
                    } else {
                        switch (metricLabel) {
                            case 'Count':
                            case 'Total Data Sent':
                            case 'Unique IPs':
                            case 'Unique Sources':
                            case 'Unique Destinations':
                                finalValue = d3.sum(valuesForAggregation, d => d.value);
                                break;
                            case '% SYN packets':
                            case '% RST packets':
                            case '% ACK packets':
                            case '% PSH packets':
                            case 'Average Inter-Arrival Time':
                                const totalValue = d3.sum(valuesForAggregation, d => d.value * d.weight);
                                const totalWeight = d3.sum(valuesForAggregation, d => d.weight);
                                finalValue = totalWeight > 0 ? totalValue / totalWeight : 0;
                                break;
                            case 'Start Time':
                                finalValue = d3.min(valuesForAggregation, d => d.value);
                                break;
                            case 'Duration':
                                finalValue = d3.max(valuesForAggregation, d => d.value);
                                break;
                            default:
                                finalValue = d3.mean(valuesForAggregation, d => d.value);
                                break;
                        }
                    }
                }
                aggregatedMetrics[metricLabel] = finalValue;
            });
            
            let totalAnomalousCount = 0;
            originalIds.forEach(originalId => {
                const countEntry = countMetricStore.find(entry => String(entry.cluster) === String(originalId));
                if (countEntry && typeof countEntry.anomalousCount === 'number') {
                    totalAnomalousCount += countEntry.anomalousCount;
                }
            });
            aggregatedMetrics['anomalousCount'] = totalAnomalousCount;

            return aggregatedMetrics;
        };

        currentLeaves.forEach(leaf => {
            const leafId = leaf.data?.cluster_id;
            if (!leafId) return;

            const stringLeafId = String(leafId);
            const isGroup = leaf.data.isGroup || false;
            const originalIds = leaf.data.originalLeaves || leaf.data.original_clusters;

            if (isGroup && originalIds && originalIds.length > 0) {
                const aggregatedMetrics = aggregateOriginalClusters(originalIds, true);
                aggregatedLeafData.set(stringLeafId, aggregatedMetrics);
            } else {
                const directData = aggregateOriginalClusters([stringLeafId], false);
                aggregatedLeafData.set(stringLeafId, directData);
            }
        });

        function updateMetadataDisplay() {
            if (!metaDataLineDiv) return;

            let metaDataParts = [];
            let clusterInfoText = `${leafCount} Clusters`;
            if (window.currentGroupingApplied && typeof window.originalLeafCount === 'number' && window.originalLeafCount > 0) {
                clusterInfoText = `${leafCount} Clusters (Original ${window.originalLeafCount})`;
            }
            metaDataParts.push(clusterInfoText);
            
            if (window.lastAppliedTimeSelection && window.lastAppliedTimeSelection.startTime && window.lastAppliedTimeSelection.endTime) {
                const { startTime, endTime } = window.lastAppliedTimeSelection;
                const durationSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
                const timeFormat = d3.timeFormat("%Y-%m-%d %H:%M:%S");
                metaDataParts.push(`Start: ${timeFormat(startTime)}`);
                metaDataParts.push(`End: ${timeFormat(endTime)}`);
                metaDataParts.push(`Duration: ${formatDuration(durationSeconds)}`);
            } else {
                metaDataParts.push("Start: N/A", "End: N/A", "Duration: N/A");
            }
            
            let totalPacketCountDendro = 0;
            let packetCountAvailable = false;
            if (aggregatedLeafData.size > 0) {
                currentLeaves.forEach(leaf => {
                    const leafIdStr = String(leaf.data?.cluster_id);
                    if (leafIdStr) {
                        const leafAggEntry = aggregatedLeafData.get(leafIdStr);
                        if (leafAggEntry && typeof leafAggEntry['Count'] === 'number') {
                            totalPacketCountDendro += leafAggEntry['Count'];
                            packetCountAvailable = true;
                        }
                    }
                });
            }
            metaDataParts.push(packetCountAvailable ? `Packets: ${totalPacketCountDendro.toLocaleString()}` : "Packets: N/A");
            
            let totalSelectedPacketCount = 0;
            let totalSelectedAnomalousPacketCount = 0;
            let isAnySelectedClusterAnomalous = false;

            if (clusterHighlightColors.size > 0) {
                clusterHighlightColors.forEach((_, clusterId) => {
                    const leafAggEntry = aggregatedLeafData.get(String(clusterId));
                    if (leafAggEntry && typeof leafAggEntry['Count'] === 'number') {
                        totalSelectedPacketCount += leafAggEntry['Count'];
                        
                        if (leafAggEntry.anomalousCount && leafAggEntry.anomalousCount > 0) {
                            isAnySelectedClusterAnomalous = true;
                            totalSelectedAnomalousPacketCount += leafAggEntry.anomalousCount;
                        }
                    }
                });
                metaDataParts.push(`Selected Packets: ${totalSelectedPacketCount.toLocaleString()}`);

                if (isAnySelectedClusterAnomalous) {
                    metaDataParts.push(`Anomalous Packets: ${totalSelectedAnomalousPacketCount.toLocaleString()}`);
                }
            }

            const separator = "&nbsp;&nbsp;|&nbsp;&nbsp;";
            metaDataLineDiv.innerHTML = metaDataParts.filter(p => p).join(separator);
        }

        // EXPOSE THE METADATA UPDATE FUNCTION TO BE CALLED EXTERNALLY
        window.updateDendrogramMetadata = updateMetadataDisplay;

        updateMetadataDisplay();

        if (selectedMetric !== 'Default' && window.fullHeatmapData && window.fullHeatmapData[selectedMetric]) {
            metricSortedLeaves.sort((a, b) => {
                const aId = String(a.data?.cluster_id);
                const bId = String(b.data?.cluster_id);
                const aData = aggregatedLeafData.get(aId);
                const bData = aggregatedLeafData.get(bId);
                const aValue = aData ? (aData[selectedMetric] ?? null) : null;
                const bValue = bData ? (bData[selectedMetric] ?? null) : null;
                if (aValue === null && bValue === null) return 0;
                if (aValue === null) return 1;
                if (bValue === null) return -1;
                const orderOption = document.getElementById("rowOrderSelect")?.value || "descending";
                return orderOption === "descending" ? bValue - aValue : aValue - bValue;
            });
        } else {
            metricSortedLeaves.sort((a, b) => a.x - b.x);
        }

        const heatmapClusterOrGroupIds = metricSortedLeaves.map(leaf => leaf.data?.cluster_id).filter(id => id !== undefined && id !== null).map(String);
        const reorderTree = reorderCheckbox.checked;
        let finalLayoutWidth;

        if (reorderTree) {
            const minLeafSpacingMetric = 20;
            const requiredWidthMetric = heatmapClusterOrGroupIds.length * minLeafSpacingMetric;
            finalLayoutWidth = Math.max(requiredWidthMetric, widthAvailableInContainer);
            const metricXScale = d3.scaleBand().domain(heatmapClusterOrGroupIds).range([margin.left, margin.left + finalLayoutWidth]).paddingInner(0);
            root.eachAfter(node => {
                if (node.children && node.children.length > 0) {
                    const validChildrenX = node.children.map(c => c.finalX).filter(x => typeof x === 'number' && isFinite(x) && x >= 0);
                    if (validChildrenX.length > 0) {
                        node.finalX = d3.mean(validChildrenX);
                    } else {
                        node.finalX = (finalLayoutWidth / 2 + margin.left);
                    }
                } else {
                    const id = node.data?.cluster_id;
                    if (id !== undefined && id !== null) {
                        const bandStart = metricXScale(String(id));
                        if (bandStart !== undefined && typeof bandStart === 'number') node.finalX = bandStart + metricXScale.bandwidth() / 2;
                        else node.finalX = -1000;
                    } else node.finalX = -1000;
                }
                if (typeof node.finalX !== 'number' || !isFinite(node.finalX)) node.finalX = (finalLayoutWidth / 2 + margin.left);
            });
        } else {
            finalLayoutWidth = structuralLayoutWidth;
            root.each(node => {
                node.finalX = node.structuralX;
                if (typeof node.finalX !== 'number' || !isFinite(node.finalX)) node.finalX = (finalLayoutWidth / 2 + margin.left);
            });
        }
        window.currentLayoutWidth = finalLayoutWidth;
        window.lastTreeRoot = root;
        window.lastTreeData = data;
        const heatmapContentWidth = finalLayoutWidth;
        const heatmapXScale = d3.scaleBand().domain(heatmapClusterOrGroupIds).range([margin.left, margin.left + heatmapContentWidth]).paddingInner(0);

        const totalNeededHeightForViewBox = height + (finalHeatmapBlockHeight > 0 ? finalHeatmapBlockHeight + heatmapSpacing : 0) + margin.top + margin.bottom;
        const viewBoxHeight = totalNeededHeightForViewBox;
        const viewBoxWidth = finalLayoutWidth + margin.left + margin.right;
        svg.attr("viewBox", `0 0 ${viewBoxWidth} ${viewBoxHeight}`).attr("preserveAspectRatio", "xMidYMid meet");

        const svgContent = svg.append("g");
        const linkGroup = svgContent.append("g").attr("class", "links-group");
        const nodeDrawingGroup = svgContent.append("g").attr("class", "nodes-group");
        const heatmapCellGroup = svgContent.append("g").attr("class", "heatmap-cells-group");
        const heatmapLineGroup = svgContent.append("g").attr("class", "heatmap-lines-group");
        const heatmapLabelGroup = svgContent.append("g").attr("class", "heatmap-labels-group");

        linkGroup.selectAll(".link").data(root.links()).join("path").attr("class", "link")
            .attr("d", d_link => {
                const sourceX = d_link.source.finalX;
                const sourceY = d_link.source.finalY + margin.top;
                const targetX = d_link.target.finalX;
                const targetY = d_link.target.finalY + margin.top;
                if ([sourceX, sourceY, targetX, targetY].every(coord => typeof coord === 'number' && isFinite(coord))) {
                    const midY = sourceY + (targetY - sourceY) / 2;
                    return `M${sourceX},${sourceY} L${sourceX},${midY} L${targetX},${midY} L${targetX},${targetY}`;
                }
                return "";
            }).attr("fill", "none").attr("stroke", "#ccc").attr("stroke-width", 1.5);

        const drawnNodes = nodeDrawingGroup.selectAll(".node")
            .data(root.descendants().filter(d_node => typeof d_node.finalX === 'number' && isFinite(d_node.finalX) && typeof d_node.finalY === 'number' && isFinite(d_node.finalY)))
            .join("g").attr("class", d_node => "node" + (d_node.children ? " node--internal" : " node--leaf") + (d_node.data.isGroup ? " node--group" : ""))
            .attr("transform", d_node => `translate(${d_node.finalX},${d_node.finalY + margin.top})`);
        drawnNodes.append("circle").attr("r", 4)
            .style("fill", d_node => d_node.data.isGroup ? "#a0a0a0" : (d_node.children ? "#555" : "#999"))
            .style("stroke", d_node => d_node.data.isGroup ? "#555" : "none").style("stroke-width", d_node => d_node.data.isGroup ? 1 : 0);

        if (features.length > 0 && heatmapClusterOrGroupIds.length > 0 && aggregatedLeafData.size > 0) {
            const heatmapFeatureData = [];
            heatmapClusterOrGroupIds.forEach(leafId => {
                const leafAggData = aggregatedLeafData.get(String(leafId));
                if (leafAggData) {
                    const leafNode = currentLeaves.find(l_node => String(l_node.data?.cluster_id) === String(leafId));
                    const isGroup = leafNode?.data?.isGroup || false;
                    const originalLeavesCount = isGroup ? (leafNode.data.originalLeaves?.length || 0) : 1;
                    const isNewCluster = newClusterIds.has(String(leafId));
                    features.forEach(metricLabel => {
                        heatmapFeatureData.push({
                            cluster_id: leafId,
                            feature: metricLabel,
                            value: leafAggData[metricLabel] ?? null,
                            anomaly: leafAggData[`${metricLabel}_anomaly`] || 'normal',
                            isGroup: isGroup,
                            originalLeavesCount: originalLeavesCount,
                            isNew: isNewCluster
                        });
                    });
                }
            });

            features.forEach(metricLabel => {
                const numericValues = heatmapFeatureData.filter(d_filter => d_filter.feature === metricLabel && d_filter.value !== null && typeof d_filter.value === 'number' && isFinite(d_filter.value)).map(d_map => d_map.value);
                let domain = [0, 1];
                if (numericValues.length > 0) {
                    const rowMin = d3.min(numericValues);
                    const rowMax = d3.max(numericValues);
                    domain = [Math.min(0, rowMin), Math.max(rowMax, rowMin + 1e-9)];
                }
                blueColorScales[metricLabel] = d3.scaleSequential(customBluesInterpolator).domain(domain).clamp(true);
                greenColorScales[metricLabel] = d3.scaleSequential(customGreensInterpolator).domain(domain).clamp(true);
            });

            featureScale.range([heatmapStartY, heatmapEndY]);

            if (heatmapXScale.bandwidth() > 0 && featureScale.bandwidth() > 0) {
                const cellSelection = heatmapCellGroup.selectAll(".heatmap-cell")
                    .data(heatmapFeatureData, d_data => `${d_data.cluster_id}-${d_data.feature}`)
                    .join("rect").attr("class", "heatmap-cell")
                    .attr("x", d_attr => {
                        const xVal = heatmapXScale(d_attr.cluster_id);
                        return (typeof xVal === 'number' && isFinite(xVal)) ? xVal : -1000;
                    })
                    .attr("width", heatmapXScale.bandwidth())
                    .attr("y", d_attr => {
                        const yVal = featureScale(d_attr.feature);
                        return (typeof yVal === 'number' && isFinite(yVal)) ? yVal : -1000;
                    })
                    .attr("height", featureScale.bandwidth());

                cellSelection.filter(function() {
                        const x = +d3.select(this).attr("x");
                        const y = +d3.select(this).attr("y");
                        return x >= -margin.left && y >= 0;
                    })
                    .each(function(d_cell) {
                        const cell = d3.select(this);
                        let currentFill;
                        let activeScale;
                        const cellClusterIdStr = String(d_cell.cluster_id);
                        const isClusterSankeyMatched = window.activeSankeyNodeFilter && window.sankeyMatchingClusterIds.has(cellClusterIdStr);

                        cell.style("opacity", 1.0);

                        if (isClusterSankeyMatched) {
                            activeScale = greenColorScales[d_cell.feature];
                        } else {
                            activeScale = blueColorScales[d_cell.feature];
                        }

                        if (d_cell.anomaly === 'anomaly' && !isClusterSankeyMatched) {
                            currentFill = anomalyOverrideColor;
                        } else if (activeScale && d_cell.value !== null && typeof d_cell.value === 'number' && isFinite(d_cell.value)) {
                            currentFill = activeScale(d_cell.value);
                        } else {
                            currentFill = isClusterSankeyMatched ? customGreensInterpolator(0.05) : customBluesInterpolator(0.01);
                        }

                        cell.attr("data-original-fill", currentFill);

                        const userClickedHighlightColor = clusterHighlightColors.get(cellClusterIdStr);
                        // *** FIX: Always use the metric-based color for the fill ***
                        cell.attr("fill", currentFill)
                            .style("stroke", userClickedHighlightColor ? userClickedHighlightColor : defaultStrokeColor)
                            .style("stroke-width", userClickedHighlightColor ? highlightStrokeWidth : defaultStrokeWidth);
                    })
                    .style("cursor", "pointer")
                    .on("click", async function(event, d_click) {
                        event.stopPropagation();
                        const clickedClusterOrGroupID = String(d_click.cluster_id);
                        const isGroupClick = d_click.isGroup;
                        const cellsForClusterOrGroup = heatmapCellGroup.selectAll('.heatmap-cell').filter(cell_d => String(cell_d.cluster_id) === clickedClusterOrGroupID);
                        if (!cellsForClusterOrGroup.empty()) {
                            cellsForClusterOrGroup.raise();
                        }

                        if (clusterHighlightColors.has(clickedClusterOrGroupID)) {
                            clusterHighlightColors.delete(clickedClusterOrGroupID);
                            addedSidebarClusters.delete(clickedClusterOrGroupID);
                            cellsForClusterOrGroup.each(function(cell_d) {
                                d3.select(this).transition().duration(100).style('stroke', defaultStrokeColor).style('stroke-width', defaultStrokeWidth);
                            });

                            if (sidebarCy) {
                                let selectorsToRemove = [];
                                if (isGroupClick) {
                                    const groupNode = currentLeaves.find(l_node => String(l_node.data?.cluster_id) === clickedClusterOrGroupID);
                                    const originalLeaves = Array.from(groupNode?.data?.originalLeaves || []);
                                    selectorsToRemove = originalLeaves.map(leafId => `[clusterID = "${leafId}"]`);

                                    originalLeaves.forEach(leafId => {
                                        clusterHighlightColors.delete(String(leafId));
                                        addedSidebarClusters.delete(String(leafId));
                                    });

                                } else {
                                    selectorsToRemove.push(`[clusterID = "${clickedClusterOrGroupID}"]`);
                                }
                                if (selectorsToRemove.length > 0) {
                                    const elesToRemove = sidebarCy.elements(selectorsToRemove.join(', '));
                                    if (elesToRemove.length > 0) sidebarCy.remove(elesToRemove);
                                }
                            }
                            if (sidebarCy && sidebarCy.elements().length > 0) {
                                applySidebarSizeControls();
                                updateLegend(sidebarCy.edges());
                                updateSidebarTableForSelectedNodesAndEdges();
                            } else {
                                clearSidebarVisualization();
                                updateLegend();
                            }
                            if (selectedNodeId && (!sidebarCy || !sidebarCy.getElementById(selectedNodeId)?.length)) {
                                deselectCurrentNode();
                                updateSidebarTableForSelectedNodesAndEdges();
                            }
                        } else {
                            if (isGroupClick) {
                                if (addedSidebarClusters.size === 0) {
                                    toggleSidebar(true);
                                }
                                const groupNode = currentLeaves.find(l_node => String(l_node.data?.cluster_id) === clickedClusterOrGroupID);
                                const originalLeaves = Array.from(groupNode?.data?.originalLeaves || []);

                                if (originalLeaves.length > 0) {
                                    const groupHighlightColor = generateUniqueHighlightColor();
                                    clusterHighlightColors.set(clickedClusterOrGroupID, groupHighlightColor);
                                    cellsForClusterOrGroup.transition().duration(100).style('stroke', groupHighlightColor).style('stroke-width', highlightStrokeWidth);

                                    originalLeaves.forEach(originalLeafId => {
                                        const stringLeafId = String(originalLeafId);
                                        if (!clusterHighlightColors.has(stringLeafId)) {
                                            clusterHighlightColors.set(stringLeafId, generateUniqueHighlightColor());
                                        }
                                    });

                                    showSidebarLoading(true, false);
                                    sidebarInfoDiv.innerHTML = `Loading network for Group ${clickedClusterOrGroupID} (${originalLeaves.length} clusters)...`;
                                    sidebarInfoDiv.style.display = 'block';
                                    let allNodesAdded = [],
                                        allEdgesAdded = [],
                                        errorOccurred = false;

                                    for (const originalLeafId of originalLeaves) {
                                        try {
                                            const response = await fetch(`${API_BASE_URL}/cluster_network?cluster_id=${originalLeafId}`);
                                            if (!response.ok) throw new Error(`Network error (${response.status})`);
                                            const clusterData = await response.json();
                                            const leafColor = clusterHighlightColors.get(String(originalLeafId)) || '#CCCCCC';

                                            if (clusterData && clusterData.nodes && clusterData.nodes.length > 0) {
                                                const nodesToAdd = clusterData.nodes.map(node_item => {
                                                    const nodeStyle = {
                                                        'background-color': leafColor
                                                    };
                                                    if (node_item.data.is_attacker) {
                                                        nodeStyle['border-color'] = 'red';
                                                        nodeStyle['border-width'] = 2;
                                                        nodeStyle['border-style'] = 'solid';
                                                    }
                                                    return {
                                                        group: 'nodes',
                                                        data: { ...node_item.data,
                                                            clusterID: originalLeafId,
                                                            Classification: node_item.data.Classification || 'Unknown'
                                                        },
                                                        style: nodeStyle,
                                                        scratch: {
                                                            _originalColor: leafColor
                                                        }
                                                    };
                                                });
                                                allNodesAdded.push(...nodesToAdd);
                                            }
                                            if (clusterData && clusterData.edges) {
                                                const edgesToAdd = clusterData.edges.map(edge => {
                                                    const protocol = edge.data.Protocol || 'Unknown';
                                                    if (!protocolColorMap[protocol]) {
                                                        let randomColor;
                                                        do {
                                                            randomColor = '#' + Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0');
                                                        } while (randomColor.toLowerCase() === SELECTED_EDGE_COLOR.toLowerCase());
                                                        protocolColorMap[protocol] = randomColor;
                                                    }
                                                    const edgeColor = protocolColorMap[protocol] || DEFAULT_UNKNOWN_COLOR;
                                                    return {
                                                        group: 'edges',
                                                        data: { ...edge.data,
                                                            clusterID: originalLeafId
                                                        },
                                                        style: {
                                                            'line-color': edgeColor,
                                                            'target-arrow-color': edgeColor
                                                        },
                                                        scratch: {
                                                            _protocolColor: edgeColor
                                                        }
                                                    };
                                                });
                                                allEdgesAdded.push(...edgesToAdd);
                                            }
                                        } catch (fetchError) {
                                            errorOccurred = true;
                                        }
                                    }
                                    showSidebarLoading(false, false);
                                    if (!sidebarCy) {
                                        sidebarCy = cytoscape({
                                            container: document.getElementById('sidebar-cy'),
                                            style: CYTOSCAPE_STYLE
                                        });
                                        bindSidebarGraphEvents();
                                    }
                                    if (allNodesAdded.length > 0 || allEdgesAdded.length > 0) {
                                        sidebarCy.add(allNodesAdded.concat(allEdgesAdded));
                                        addedSidebarClusters.add(clickedClusterOrGroupID);
                                        originalLeaves.forEach(leafId => addedSidebarClusters.add(String(leafId)));
                                        applySidebarSizeControls();
                                        applySidebarLayout();
                                        sidebarCy.fit(null, 30);
                                        sidebarInfoDiv.style.display = 'none';
                                        updateLegend(sidebarCy.edges());
                                        loadSidebarClusterTable(originalLeaves[0], 1);
                                    } else if (!errorOccurred) {
                                        sidebarInfoDiv.innerHTML = `Group ${clickedClusterOrGroupID}: No network data.`;
                                        addedSidebarClusters.add(clickedClusterOrGroupID);
                                        loadSidebarClusterTable(originalLeaves[0], 1);
                                    } else {
                                        sidebarInfoDiv.innerHTML = `Group ${clickedClusterOrGroupID}: Some data could not load.`;
                                        if (sidebarCy.elements().length > 0) {
                                            addedSidebarClusters.add(clickedClusterOrGroupID);
                                            originalLeaves.forEach(leafId => addedSidebarClusters.add(String(leafId)));
                                            applySidebarSizeControls();
                                            applySidebarLayout();
                                            sidebarCy.fit(null, 30);
                                            updateLegend(sidebarCy.edges());
                                        }
                                        loadSidebarClusterTable(originalLeaves[0], 1);
                                    }
                                    deselectCurrentNode();
                                } else {
                                    sidebarInfoDiv.innerHTML = `Group ${clickedClusterOrGroupID}: No underlying clusters.`;
                                    showSidebarLoading(false, false);
                                }
                            } else {
                                const targetHighlightColor = generateUniqueHighlightColor();
                                clusterHighlightColors.set(clickedClusterOrGroupID, targetHighlightColor);
                                cellsForClusterOrGroup.transition().duration(100).style('stroke', targetHighlightColor).style('stroke-width', highlightStrokeWidth);
                                const isClusterAnomalous = d_click.anomaly === 'anomaly';
                                visualizeClusterInSidebar(clickedClusterOrGroupID, targetHighlightColor, isClusterAnomalous);
                            }
                        }
                        
                        updateMetadataDisplay();
                        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                        updateSubtreeButtonState();
                    })
                    .on("mouseover", function(event, d_mouseover) {
                        const cell = d3.select(this);
                        cell.attr('data-hover-temp-stroke', cell.style('stroke'));
                        cell.attr('data-hover-temp-stroke-width', cell.style('stroke-width'));
                        cell.style("stroke", "black").style("stroke-width", 1.5);
                        const tooltip = d3.select("#tooltip");
                        const metricLabel = d_mouseover.feature;
                        const clusterOrGroupId = d_mouseover.cluster_id;
                        const value = d_mouseover.value;
                        const anomalyStatusCell = d_mouseover.anomaly === 'anomaly' ? 'Anomaly Detected' : 'Normal';
                        const isGroup = d_mouseover.isGroup;
                        const originalCount = d_mouseover.originalLeavesCount;
                        let displayValue = 'N/A';
                        if (value !== null && typeof value === 'number' && isFinite(value)) {
                            if (metricLabel.includes('%')) displayValue = `${value.toFixed(2)}%`;
                            else if (Number.isInteger(value)) displayValue = value.toLocaleString();
                            else {
                                const valueStr = String(value);
                                displayValue = (valueStr.includes('e') || valueStr.includes('E')) ? value.toExponential(2) : value.toFixed(3);
                            }
                        }
                        let titleText = isGroup ? `Group: ${clusterOrGroupId} (${originalCount} clusters)` : `Cluster: ${clusterOrGroupId}`;
                        let tooltipHtml = `${titleText}<br>Metric: ${metricLabel}<br>Value: ${displayValue}<br>Status: ${anomalyStatusCell}`;
                        let clusterAttackTypes = [];
                        if (window.fullHeatmapData && window.fullHeatmapData['Count']) {
                            const clusterEntry = window.fullHeatmapData['Count'].find(entry => String(entry.cluster) === String(clusterOrGroupId));
                            if (clusterEntry && clusterEntry.ClusterAttackTypes && clusterEntry.ClusterAttackTypes.length > 0) clusterAttackTypes = clusterEntry.ClusterAttackTypes;
                        }
                        if (clusterAttackTypes.length > 0) tooltipHtml += `<br><strong style="color:purple;">Cluster Attacks: ${clusterAttackTypes.join(', ')}</strong>`;
                        tooltip.style("display", "block").html(tooltipHtml).style("left", (event.pageX + 10) + "px").style("top", (event.pageY - 15) + "px");
                    })
                    .on("mouseout", function(event, d_mouseout) {
                        d3.select("#tooltip").style("display", "none");
                        const cell = d3.select(this);
                        const originalStroke = cell.attr('data-hover-temp-stroke');
                        const originalStrokeWidth = cell.attr('data-hover-temp-stroke-width');
                        if (originalStroke && originalStrokeWidth) {
                            cell.style("stroke", originalStroke).style("stroke-width", originalStrokeWidth);
                            cell.attr('data-hover-temp-stroke', null);
                            cell.attr('data-hover-temp-stroke-width', null);
                        } else {
                            const cellClusterIdStr = String(d_mouseout.cluster_id);
                            const userClickedHighlightColor = clusterHighlightColors.get(cellClusterIdStr);
                            cell.style("stroke", userClickedHighlightColor ? userClickedHighlightColor : defaultStrokeColor).style("stroke-width", userClickedHighlightColor ? highlightStrokeWidth : defaultStrokeWidth);
                        }
                    });

                cellSelection.filter(d_filter_new => d_filter_new.isNew).each(function(dCell_new) {
                    const cellRect = d3.select(this);
                    const x = parseFloat(cellRect.attr("x"));
                    const y = parseFloat(cellRect.attr("y"));
                    const width = parseFloat(cellRect.attr("width"));
                    const height = parseFloat(cellRect.attr("height"));
                    if (!isNaN(x) && !isNaN(y) && !isNaN(width) && !isNaN(height)) {
                        heatmapLineGroup.append("line").attr("class", "new-cluster-indicator").attr("x1", x).attr("y1", y + height + 1).attr("x2", x + width).attr("y2", y + height + 1).attr("stroke", "red").attr("stroke-width", 1.5).attr("data-cluster-ref", dCell_new.cluster_id);
                    }
                });

                heatmapLabelGroup.selectAll(".heatmap-feature-label").data(features).join("text").attr("class", "heatmap-feature-label").attr("x", margin.left - 5)
                    .attr("y", d_label => {
                        const yVal = featureScale(d_label);
                        return (typeof yVal === 'number' && isFinite(yVal)) ? yVal + featureScale.bandwidth() / 2 : -1000;
                    })
                    .attr("text-anchor", "end").attr("dominant-baseline", "middle").attr("font-size", "9px").text(d_label => d_label);
                const metricSelectElement = document.getElementById('dendrogramSortMetricSelect');
                const selectedMetricValue = metricSelectElement ? metricSelectElement.value : 'Default';
                const selectedMetricLabelText = metricSelectElement ? metricSelectElement.options[metricSelectElement.selectedIndex].text : null;
                const featureLabels = heatmapLabelGroup.selectAll(".heatmap-feature-label");
                featureLabels.style("fill", "#333").style("font-weight", "normal");
                if (selectedMetricValue !== 'Default' && selectedMetricLabelText) {
                    featureLabels.filter(function(d_filter_label) {
                        return d_filter_label === selectedMetricLabelText;
                    }).style("fill", "#4299e1").style("font-weight", "bold");
                }
            }
        }

        let dx = 0,
            dy = 0,
            initialScale = 1;
        try {
            const bounds = svgContent.node()?.getBBox();
            if (bounds && bounds.width > 0 && bounds.height > 0) {
                const scaleX = viewBoxWidth / bounds.width;
                const scaleY = viewBoxHeight / bounds.height;
                initialScale = Math.min(scaleX, scaleY) * 0.95;
                initialScale = Math.max(0.05, Math.min(initialScale, 5));
                dx = (viewBoxWidth / 2) - ((bounds.x + bounds.width / 2) * initialScale);
                dy = (viewBoxHeight / 2) - ((bounds.y + bounds.height / 2) * initialScale);
                if (!isFinite(dx)) dx = margin.left;
                if (!isFinite(dy)) dy = margin.top;
                if (!isFinite(initialScale) || initialScale <= 0) initialScale = 1;
            } else {
                dx = margin.left;
                dy = margin.top;
                initialScale = 1;
            }
        } catch (e) {
            dx = margin.left;
            dy = margin.top;
            initialScale = 1;
        }
        initialTreeTransform = d3.zoomIdentity.translate(dx, dy).scale(initialScale);
        const zoomBehavior = d3.zoom().scaleExtent([0.05, 10])
            .on("zoom.main", (event) => {
                svgContent.attr("transform", event.transform);
                const thresholdSliderElem = document.getElementById('thresholdSlider');
                if (thresholdSliderElem && window.lastTreeRoot && svgContent.node()) {
                    requestAnimationFrame(() => {
                        thresholdSliderElem.dispatchEvent(new Event('input'));
                    });
                } else {
                    d3.select("#threshold-bar").style("display", "none");
                }
            });
        window.inlineZoom = zoomBehavior;
        svg.call(zoomBehavior).call(zoomBehavior.transform, initialTreeTransform).on("dblclick.zoom", null);
        
        if (treeControls) {
            treeControls.style.display = "flex";
            treeControls.style.opacity = '1';
            treeControls.style.pointerEvents = 'auto';
            treeControls.querySelectorAll('button, input, select').forEach(ctrl => ctrl.disabled = false);
        }

        try {
            previousClusterCount = leafCount;
            previousClusterHash = JSON.stringify(data);
        } catch (e) {}
        highlightTreeClusters(new Set(clusterHighlightColors.keys()));
        const initialSlider = document.getElementById('thresholdSlider');
        if (initialSlider && window.lastTreeRoot && svgContent.node()) {
            requestAnimationFrame(() => {
                initialSlider.dispatchEvent(new Event('input'));
            });
        } else {
            d3.select("#threshold-bar").style("display", "none");
        }
        
        updateControlsState();
        updateSubtreeButtonState();
    }

    function resetGroupingAndRedraw() {
        console.log("Resetting grouping...");
        const messageDiv = document.getElementById('reclusterMessage');
        const thresholdSlider = document.getElementById('thresholdSlider');
        const thresholdValueSpan = document.getElementById('thresholdValue');

        // MOVED: Clear selections and highlights before redrawing
        clearSidebarVisualization(); 
        updateLegend(); 

        if (!window.originalTreeData) {
            console.error("Cannot reset grouping: Original tree data is missing.");
            alert("Error: Cannot reset grouping, original data not found.");
            if (messageDiv) messageDiv.textContent = "Error: Original data missing.";
            return;
        }

        // Restore original data and state
        window.lastTreeData = window.originalTreeData;
        window.currentGroupingApplied = false;
        window.lastAppliedThreshold = 100;
        
        try {
            window.lastTreeRoot = d3.hierarchy(window.originalTreeData); 
            console.log("Restored original tree data and reset grouping state. lastTreeRoot updated.");
        } catch (e) {
            console.error("Error creating hierarchy from originalTreeData on reset:", e, window.originalTreeData);
            alert("Error restoring original tree structure.");
            showInlineDendrogram(null); 
            return;
        }

        if (messageDiv) messageDiv.textContent = '';

        // Redraw the dendrogram with the original (ungrouped) data
        showInlineDendrogram(window.originalTreeData, currentDendrogramHeight); 

        if (thresholdSlider) {
            thresholdSlider.value = 100;
            requestAnimationFrame(() => {
                if (window.lastTreeRoot && window.lastTreeRoot.data === window.originalTreeData) {
                    thresholdSlider.dispatchEvent(new Event('input'));
                } else {
                    console.warn("Skipping threshold bar update on reset; lastTreeRoot might not be original.")
                }
            });
            console.log("Reset threshold slider visually.");
        }

        // Update button states
        updateControlsState();
        updateSubtreeButtonState();

        console.log("Grouping reset to the original state.");
    }
    
    function updateControlsState() {
        const groupingApplied = window.currentGroupingApplied || false; // Default to false if undefined

        // Get references to the controls
        const resetGroupingBtn = document.getElementById('resetGroupingBtn');
        const resolutionInput = document.getElementById('resolutionInput');
        const applyResolutionBtn = document.getElementById('applyResolutionBtn'); // Find button by its ID
        const applyThresholdBtn = document.getElementById('applyThresholdBtn'); // Get Apply Threshold button

        // --- Reset Grouping Button ---
        if (resetGroupingBtn) {
            resetGroupingBtn.disabled = !groupingApplied; // ENABLED only if grouping IS applied
            console.log(`Reset Grouping Button disabled: ${!groupingApplied}`);
        } else { console.error("Reset Grouping Button not found in updateControlsState"); }

        // --- Resolution Controls ---
        if (resolutionInput) {
            resolutionInput.disabled = groupingApplied; // Disable Resolution input if grouping IS applied
            console.log(`Resolution Input disabled: ${groupingApplied}`);
        } else { console.error("Resolution Input not found in updateControlsState"); }

        if (applyResolutionBtn) {
            applyResolutionBtn.disabled = groupingApplied; // Disable Apply Resolution button if grouping IS applied
            console.log(`Apply Resolution Button disabled: ${groupingApplied}`);
        } else { console.error("Apply Resolution Button not found in updateControlsState"); }

        // --- Apply Threshold Button ---
        if (applyThresholdBtn) {
            applyThresholdBtn.disabled = false; // Explicitly ensure it's always enabled
            console.log(`Apply Threshold Button disabled: false`); // Log that it's enabled
        } else { console.error("Apply Threshold Button not found in updateControlsState"); }
    }

    function applyThresholdGrouping() {
        console.log("Applying threshold grouping...");
        const thresholdSlider = document.getElementById('thresholdSlider');
        const messageDiv = document.getElementById('reclusterMessage');

        const currentRawData = window.lastTreeData;
        const layoutHeight = window.currentD3LayoutHeight;

        if (!currentRawData) {
            console.error("Cannot apply grouping: Currently displayed tree data (window.lastTreeData) is missing.");
            alert("Error: Cannot apply threshold, current tree data is missing.");
            return;
        }

        if (!layoutHeight || layoutHeight <= 0) {
            console.error("Cannot apply grouping: currentD3LayoutHeight is invalid or not set.", layoutHeight);
            alert("Error: Layout height information is missing or invalid for thresholding. Please ensure the dendrogram is displayed correctly.");
            return;
        }

        if (!thresholdSlider) {
            console.error("Cannot apply grouping: Missing thresholdSlider element.");
            alert("Error: Could not apply threshold grouping. UI element missing.");
            return;
        }

        const physicalValue = parseInt(thresholdSlider.value, 10);
        const currentDisplayMaxBeforeApply = window.lastAppliedThreshold;
        const scaledPercentageToApply = Math.round((physicalValue / 100) * currentDisplayMaxBeforeApply);

        console.log(`Physical slider: ${physicalValue}%, Current Display Max: ${currentDisplayMaxBeforeApply}%, Scaled Pct to Apply: ${scaledPercentageToApply}%`);

        if (scaledPercentageToApply >= currentDisplayMaxBeforeApply && currentDisplayMaxBeforeApply < 100) {
            alert(`To create a new grouping, the threshold (${scaledPercentageToApply}%) must be less than the current displayed maximum of ${currentDisplayMaxBeforeApply}%.`);
            return;
        }
        if (scaledPercentageToApply >= 100) {
            alert("Threshold must be below 100% to apply grouping. To see the full tree, use Reset Grouping.");
            return;
        }

        const thresholdLayoutY = layoutHeight * (scaledPercentageToApply / 100);
        console.log(`Thresholding tree at displayed ${scaledPercentageToApply}%. Effective Layout Y for grouping: ${thresholdLayoutY.toFixed(2)} (based on full Layout Height: ${layoutHeight.toFixed(2)})`);

        let workingRootHierarchy;
        try {
            workingRootHierarchy = d3.hierarchy(structuredClone(currentRawData));
        } catch (e) {
            console.error("Error deep cloning current tree data for grouping:", e);
            alert("Error preparing data for grouping.");
            return;
        }

        const tempTreeLayout = d3.cluster().size([1, layoutHeight]);
        tempTreeLayout(workingRootHierarchy);

        workingRootHierarchy.each(node => {
            node.structuralY = node.y;
            if (typeof node.structuralY !== 'number' || !isFinite(node.structuralY)) {
                node.structuralY = (node.parent && typeof node.parent.structuralY === 'number' && isFinite(node.parent.structuralY))
                                    ? node.parent.structuralY
                                    : 0;
                console.warn(`Fell back to parent's Y or 0 for node:`, node.data.id || node.data.cluster_id);
            }
        });

        const nodesToPrune = new Set();
        const groupRepresentations = new Map();
        let groupingOccurred = false;

        workingRootHierarchy.eachAfter(node => {
            const isBelowThreshold = node.structuralY > thresholdLayoutY + 1e-6;

            if (isBelowThreshold && !nodesToPrune.has(node)) {
                groupingOccurred = true;
                let representativeAncestor = node.parent;
                while (representativeAncestor && (representativeAncestor.structuralY > thresholdLayoutY + 1e-6)) {
                    representativeAncestor = representativeAncestor.parent;
                }
                representativeAncestor = representativeAncestor || node;

                const repAncestorOriginalId = representativeAncestor.data.id || `dist${representativeAncestor.data.dist.toFixed(4)}`;
                const repAncestorDataId = `rep_${repAncestorOriginalId}`;

                if (!groupRepresentations.has(repAncestorDataId)) {
                    const groupId = `GROUP_of_${repAncestorOriginalId}_at_${scaledPercentageToApply}%`; // Use scaledPercentageToApply in ID
                    const groupNodeData = {
                        id: groupId,
                        dist: representativeAncestor.data.dist,
                        isGroup: true,
                        cluster_id: groupId,
                        originalLeaves: new Set(),
                    };
                    groupRepresentations.set(repAncestorDataId, {
                        representativeNodeData: groupNodeData,
                        originalLeavesSet: groupNodeData.originalLeaves
                    });
                }

                const groupInfo = groupRepresentations.get(repAncestorDataId);

                node.leaves().forEach(leafOfCurrentSubtree => {
                    if (leafOfCurrentSubtree.data.isGroup && leafOfCurrentSubtree.data.originalLeaves) {
                        (Array.isArray(leafOfCurrentSubtree.data.originalLeaves) ? leafOfCurrentSubtree.data.originalLeaves : Array.from(leafOfCurrentSubtree.data.originalLeaves)).forEach(originalLeafId => {
                            groupInfo.originalLeavesSet.add(String(originalLeafId));
                        });
                    } else if (leafOfCurrentSubtree.data.cluster_id !== undefined && leafOfCurrentSubtree.data.cluster_id !== null) {
                        groupInfo.originalLeavesSet.add(String(leafOfCurrentSubtree.data.cluster_id));
                    }
                });
                node.descendants().forEach(descendant => nodesToPrune.add(descendant));
            }
        });

        if (!groupingOccurred) {
            alert("No clusters fall below the selected threshold. No grouping applied.");
            if (messageDiv) messageDiv.textContent = "No change: threshold did not cause grouping.";
            if (thresholdSlider) {
                requestAnimationFrame(() => { thresholdSlider.dispatchEvent(new Event('input')); });
            }
            return;
        }

        function buildCompressedTreeData(currentHierarchyNode) {
            if (nodesToPrune.has(currentHierarchyNode)) {
                let representativeAncestor = currentHierarchyNode.parent;
                while (representativeAncestor && (representativeAncestor.structuralY > thresholdLayoutY + 1e-6)) {
                    representativeAncestor = representativeAncestor.parent;
                }
                representativeAncestor = representativeAncestor || currentHierarchyNode;

                const repAncestorOriginalId = representativeAncestor.data.id || `dist${representativeAncestor.data.dist.toFixed(4)}`;
                const repAncestorDataId = `rep_${repAncestorOriginalId}`;

                if (groupRepresentations.has(repAncestorDataId)) {
                    return groupRepresentations.get(repAncestorDataId).representativeNodeData;
                } else {
                    console.error("Critical Error: Pruned node has no group representation during tree build:", currentHierarchyNode.data);
                    return null;
                }
            }

            const newNodeData = { ...currentHierarchyNode.data };
            delete newNodeData.children;

            if (currentHierarchyNode.children && currentHierarchyNode.children.length > 0) {
                const newChildrenList = [];
                currentHierarchyNode.children.forEach(childHierarchyNode => {
                    const newChildData = buildCompressedTreeData(childHierarchyNode);
                    if (newChildData) {
                        if (!newChildrenList.some(existingChild => existingChild.id === newChildData.id)) {
                            newChildrenList.push(newChildData);
                        }
                    }
                });
                if (newChildrenList.length > 0) {
                    newNodeData.children = newChildrenList;
                }
            }
            return newNodeData;
        }

        let compressedTreeData = buildCompressedTreeData(workingRootHierarchy);

        if (!compressedTreeData) {
            console.error("Failed to build compressed tree data. The root itself might have been erroneously pruned or unrepresented.");
            alert("Error: Failed to apply threshold grouping due to an issue in tree reconstruction.");
            return;
        }

        function convertOriginalLeavesSetToArray(node) {
            if (node.isGroup && node.originalLeaves instanceof Set) {
                node.originalLeaves = Array.from(node.originalLeaves);
            }
            if (node.children) {
                node.children.forEach(convertOriginalLeavesSetToArray);
            }
        }
        convertOriginalLeavesSetToArray(compressedTreeData);

        console.log("Compressed tree structure generated:", compressedTreeData);
        window.lastTreeData = compressedTreeData;
        window.currentGroupingApplied = true;
        window.lastAppliedThreshold = scaledPercentageToApply;
        console.log(`Updated window.lastAppliedThreshold to: ${window.lastAppliedThreshold}%`);

        try {
            window.lastTreeRoot = d3.hierarchy(compressedTreeData);
        } catch (e) {
            console.error("Error creating hierarchy from compressed data:", e, compressedTreeData);
            alert("Error finalizing grouped tree structure.");
            return;
        }

        showInlineDendrogram(compressedTreeData, currentDendrogramHeight);

        console.log(`Threshold applied. Clusters below displayed ${scaledPercentageToApply}% merged. Tree and heatmap redrawn.`);
        if (messageDiv) messageDiv.textContent = '';

        clearSidebarVisualization();
        if(isSidebarOpen) toggleSidebar(false);
        updateLegend();

        if (thresholdSlider) {
            thresholdSlider.value = 100; // Set physical slider to max
            requestAnimationFrame(() => { thresholdSlider.dispatchEvent(new Event('input')); });
            console.log("Physical threshold slider reset to 100% position after apply. Displayed text will update.");
        }

        updateControlsState();
        updateSubtreeButtonState(); // ADD THIS CALL AT THE END
    }

    function highlightTreeClusters(selectedClusterIds = new Set()) {
        const svgContent = d3.select("#inlineDendrogramSvg g");
        if (svgContent.empty()) {
            return; // Tree not rendered yet
        }

        const leafNodes = svgContent.selectAll(".node--leaf"); // Select the group containing circle and text
        const leafCircles = leafNodes.select("circle");
        const leafTexts = leafNodes.select("text");
        const defaultTextColor = "#333"; // Default text color

        // Reset all leaves first
        leafCircles.classed("highlighted", false)
                  .transition().duration(150)
                  .attr("r", 4) // Default radius
                  .style("fill", "#999") // Default leaf circle color
                  .style("stroke", "none");

        leafTexts.transition().duration(150)
                .style("fill", defaultTextColor) // Reset text color
                .style("font-weight", "normal"); // Reset font weight

        // Apply highlights based on the provided set and stored colors
        if (selectedClusterIds.size > 0) {
            selectedClusterIds.forEach(clusterId => {
                const stringClusterId = String(clusterId); // Ensure string comparison
                // Get the correct highlight color from the global map
                const highlightColor = clusterHighlightColors.get(stringClusterId);

                if (highlightColor) { // Only highlight if found in the map
                    // Find the matching leaf node(s)
                    const matchedNodes = leafNodes.filter(function(d) {
                        return d && d.data && String(d.data.cluster_id) === stringClusterId;
                    });

                    // Highlight the circle
                    matchedNodes.select("circle")
                        .classed("highlighted", true)
                        .transition().duration(150)
                        .attr("r", 6) // Highlighted radius
                        .style("fill", highlightColor) // Use the specific highlight color from map
                        .style("stroke", "none");

                    // --- Modify Text Color ---
                    try {
                        // Parse the highlight color (assuming HSL format like "hsl(H, S%, L%)")
                        let color = d3.hsl(highlightColor);

                        // Lower saturation (e.g., reduce by 40%, ensure it's between 0 and 1)
                        color.s = Math.max(0, Math.min(1, color.s * 0.6));

                        // Optional: Slightly increase lightness for readability, especially if saturation is low
                        if (color.s < 0.3) {
                            color.l = Math.min(1, color.l + 0.1);
                        }
                        // Ensure lightness isn't too high (avoid white on white)
                        color.l = Math.min(0.85, color.l);

                        const textColor = color.toString(); // Convert back to string

                        // Apply the modified color to the text
                        matchedNodes.select("text")
                            .transition().duration(150)
                            .style("fill", textColor)
                            .style("font-weight", "bold"); // Make text bold for emphasis

                    } catch (e) {
                        console.error("Could not parse highlight color for text:", highlightColor, e);
                        // Fallback: Apply a default highlight color to text if parsing fails
                        matchedNodes.select("text")
                            .transition().duration(150)
                            .style("fill", "#d95f02") // Fallback color (dark orange)
                            .style("font-weight", "bold");
                    }
                    // --- End Text Color Modification ---

                } else {
                    console.warn(`Highlight color not found in map for cluster ${stringClusterId}`);
                }
            });
        }
    }

    function hideDendrogram() {
        const card = document.getElementById('dendrogramCard');
        const showButton = document.getElementById('showTreeBtn');
        card.style.display = 'none';
        showButton.style.display = 'inline-block'; // Show the 'Show Tree' button
        console.log("Dendrogram hidden.");
    }

    function showDendrogram() {
        const card = document.getElementById('dendrogramCard');
        const showButton = document.getElementById('showTreeBtn');
        card.style.display = 'block';    // Show the card
        showButton.style.display = 'none'; // Hide the 'Show Tree' button

        // Optional: Reload or redraw if needed when shown
        if (!window.lastTreeData) {
            console.log("No tree data, loading...");
            loadInlineDendrogram(); // Load data if it wasn't loaded before
        } else {
            console.log("Showing existing dendrogram.");
            // You could potentially redraw or fit view here if desired
            // showInlineDendrogram(window.lastTreeData, document.getElementById("inline-dendrogram-container").clientHeight);
            // resetInlineZoom();
        }
    }
    
    // Optional Helper Function to fit view (Example)
    function fitView() {
        const svg = d3.select("#inlineDendrogramSvg");
        const svgContent = svg.select("g"); // Assumes content is in the first 'g'
        if (!svgContent.empty() && window.inlineZoom) {
            const bounds = svgContent.node().getBBox();
            const parent = svg.node();
            const fullWidth = parent.clientWidth;
            const fullHeight = parent.clientHeight;
            const width = bounds.width;
            const height = bounds.height;
            const midX = bounds.x + width / 2;
            const midY = bounds.y + height / 2;

            if (width === 0 || height === 0) return; // Nothing to fit

            const scale = 0.9 / Math.max(width / fullWidth, height / fullHeight);
            const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];

            svg.transition().duration(750).call(
                window.inlineZoom.transform,
                d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
            );
        }
    }

    function resetInlineZoom() {
        const svg = d3.select("#inlineDendrogramSvg");
        if (window.inlineZoom) {
            // Reset zoom with a smooth transition TO THE STORED INITIAL CENTERED TRANSFORM
            svg.transition().duration(500)
                .call(window.inlineZoom.transform, initialTreeTransform);
            console.log("Inline dendrogram zoom reset to initial view.");
        } else {
            console.warn("Cannot reset zoom, zoom behavior not initialized.");
        }
    }

    function loadInlineDendrogram() {
        console.log("Attempting to load inline dendrogram data...");
        currentNewClusterIds.clear();

        let url = new URL(`${API_BASE_URL}/hierarchical_clusters`);

        if (window.lastAppliedTimeSelection && window.lastAppliedTimeSelection.startTime) {
            url.searchParams.append('start_time', window.lastAppliedTimeSelection.startTime.toISOString());
            url.searchParams.append('end_time', window.lastAppliedTimeSelection.endTime.toISOString());
        }

        const resolutionInput = document.getElementById('resolutionInput');
        if (resolutionInput && resolutionInput.value) {
            url.searchParams.append('resolution', resolutionInput.value);
        }

        return fetch(url.toString(), { signal: globalAbortController.signal })
            .then(response => {
                if (!response.ok) {
                    return response.json().catch(() => response.text())
                    .then(errBody => {
                        let errMsg = errBody?.error || errBody || `HTTP error ${response.status}`;
                        throw new Error(errMsg);
                    });
                }
                return response.json();
            })
            .then(data => {
                if (globalAbortController.signal.aborted) {
                    console.log("Dendrogram loading aborted before processing data.");
                    throw new DOMException("Operation aborted by user.", "AbortError");
                }
                console.log("Dendrogram data received:", data);
                if (Object.keys(data).length === 0 || (data.error)) {
                    window.originalTreeData = null;
                    window.lastTreeData = null;
                    window.originalLeafCount = 0;
                    showInlineDendrogram(null, undefined, currentNewClusterIds);
                } else {
                    try {
                        window.originalTreeData = structuredClone(data);
                        const originalRoot = d3.hierarchy(window.originalTreeData);
                        window.originalLeafCount = originalRoot.leaves().length;
                    } catch (cloneError) {
                        window.originalTreeData = data;
                        try {
                            const originalRoot = d3.hierarchy(window.originalTreeData);
                            window.originalLeafCount = originalRoot.leaves().length;
                        } catch (countError) {
                            window.originalLeafCount = 0;
                        }
                    }
                    window.currentGroupingApplied = false;
                    window.lastAppliedThreshold = 100;
                    const thresholdSlider = document.getElementById('thresholdSlider');
                    const thresholdValue = document.getElementById('thresholdValue');
                    if(thresholdSlider) thresholdSlider.value = 100;
                    if(thresholdValue) thresholdValue.textContent = '100%';
                    const reclusterMsg = document.getElementById('reclusterMessage');
                    if (reclusterMsg) reclusterMsg.textContent = '';
                    showInlineDendrogram(data, undefined, currentNewClusterIds);
                }
                return Promise.resolve();
            })
            .catch(err => {
                if (err.name === 'AbortError') {
                    console.log("Dendrogram loading was aborted.");
                } else {
                    console.error("Failed to load or render inline dendrogram:", err);
                }
                window.originalTreeData = null;
                window.lastTreeData = null;
                window.originalLeafCount = 0;
                showInlineDendrogram(null, undefined, currentNewClusterIds);
                return Promise.reject(err);
            });
    }

    function formatDuration(seconds) {
        if (seconds === null || seconds === undefined || isNaN(seconds) || seconds < 0) {
            return "N/A";
        }
        if (seconds < 60) {
            return `${seconds.toFixed(2)}s`;
        }
        let minutes = Math.floor(seconds / 60);
        let remainingSeconds = Math.floor(seconds % 60);
        if (minutes < 60) {
            return `${minutes}m ${remainingSeconds}s`;
        }
        let hours = Math.floor(minutes / 60);
        let remainingMinutes = minutes % 60;
        if (hours < 24) {
            return `${hours}h ${remainingMinutes}m ${remainingSeconds}s`;
        }
        let days = Math.floor(hours / 24);
        let remainingHours = hours % 24;
        return `${days}d ${remainingHours}h ${remainingMinutes}m`;
    }

    async function updateTimeInfoDisplay() {
        currentDisplayableTimeInfo = {
            start: "Start: N/A",
            end: "End: N/A",
            duration: "Duration: N/A",
            isSet: false
        };

        try {
            const response = await fetch(`${API_BASE_URL}/time_info`);
            if (!response.ok) {
                let errorMsg = `HTTP error ${response.status}`;
                let errorDetails = "";
                try {
                    const errData = await response.json();
                    errorMsg = errData.error || errorMsg;
                    errorDetails = JSON.stringify(errData);
                } catch (e) {
                    errorDetails = await response.text().catch(() => "Could not retrieve error body.");
                    errorMsg = response.statusText || errorMsg;
                }
                console.error(`updateTimeInfoDisplay: Failed to fetch time info. Status: ${response.status}, Message: ${errorMsg}, Details: ${errorDetails}`);
                return; // Exit if fetch fails
            }
            
            const data = await response.json();

            if (data &&
                typeof data.start_time === 'string' && data.start_time &&
                typeof data.end_time === 'string' && data.end_time &&
                data.duration_seconds !== null && typeof data.duration_seconds !== 'undefined' && !isNaN(parseFloat(data.duration_seconds))) {

                let startTimeStr = "N/A";
                let endTimeStr = "N/A";

                try {
                    const startDate = new Date(data.start_time);
                    if (!isNaN(startDate.getTime())) {
                        startTimeStr = startDate.toLocaleString();
                    } else {
                        startTimeStr = "N/A (bad date)";
                    }
                } catch (e) {
                    startTimeStr = "N/A (parse error)";
                }

                try {
                    const endDate = new Date(data.end_time);
                    if (!isNaN(endDate.getTime())) {
                        endTimeStr = endDate.toLocaleString();
                    } else {
                        endTimeStr = "N/A (bad date)";
                    }
                } catch (e) {
                    endTimeStr = "N/A (parse error)";
                }
                
                const durationFormatted = formatDuration(parseFloat(data.duration_seconds));

                currentDisplayableTimeInfo.start = `Start: ${startTimeStr}`;
                currentDisplayableTimeInfo.end = `End: ${endTimeStr}`;
                currentDisplayableTimeInfo.duration = `Duration: ${durationFormatted}`;
                currentDisplayableTimeInfo.isSet = true;
            }
        } catch (error) {
            console.error('updateTimeInfoDisplay: Exception during fetch or processing time info:', error);
        }
    }

    async function reclusterAndRedraw() {
        const resolutionInput = document.getElementById('resolutionInput');
        const messageDiv = document.getElementById('reclusterMessage');
        const acknowledgeBtn = document.getElementById('acknowledgeNewClustersBtn');
        const treeInfoSpan = document.getElementById('treeInfoSpan');

        let resolution;
        const inputValue = resolutionInput.value.trim();

        if (inputValue === "") {
            resolution = 2.5;
        } else {
            resolution = parseFloat(inputValue);
        }

        if (isNaN(resolution) || resolution <= 0) {
            messageDiv.textContent = "Please enter a valid resolution > 0.";
            messageDiv.style.color = '#e53e3e';
            if (acknowledgeBtn) acknowledgeBtn.style.display = 'none';
            resolutionInput.focus();
            return;
        }

        messageDiv.textContent = "Applying resolution and reclustering...";
        messageDiv.style.color = '#333';
        if (acknowledgeBtn) acknowledgeBtn.style.display = 'none';
        if (treeInfoSpan) treeInfoSpan.textContent = '';
        console.log(`Requesting recluster with resolution: ${resolution}`);
        showLoading();

        previousClusterIdsBeforeRecluster.clear();
        if (window.originalTreeData) {
            try {
                const oldRoot = d3.hierarchy(window.originalTreeData);
                oldRoot.leaves().forEach(leaf => {
                    if (leaf.data && leaf.data.cluster_id !== undefined) {
                        previousClusterIdsBeforeRecluster.add(String(leaf.data.cluster_id));
                    }
                });
            } catch (e) {
                console.warn("Could not get previous cluster IDs from originalTreeData:", e);
            }
        }

        try {
            const response = await fetch(`${API_BASE_URL}/hierarchical_clusters?resolution=${resolution}`, { signal: globalAbortController.signal });
            if (globalAbortController.signal.aborted) {
                console.log("Recluster fetch completed but operation was aborted before processing.");
                throw new DOMException("Operation aborted by user.", "AbortError");
            }
            if (!response.ok) {
                const errBody = await response.json().catch(() => response.text());
                throw new Error(errBody.error || errBody || `HTTP error ${response.status}`);
            }
            const treeData = await response.json();
            console.log("Reclustered tree data received:", treeData);

            if (globalAbortController.signal.aborted) {
                console.log("Reclustering aborted before updating heatmap and dendrogram.");
                throw new DOMException("Operation aborted by user.", "AbortError");
            }

            window.originalTreeData = structuredClone(treeData);
            const newOriginalRoot = d3.hierarchy(window.originalTreeData);
            window.originalLeafCount = newOriginalRoot.leaves().length;

            await updateHeatmap();

            if (globalAbortController.signal.aborted) {
                throw new DOMException("Operation aborted by user.", "AbortError");
            }
            window.currentGroupingApplied = false;
            window.lastAppliedThreshold = 100;
            const thresholdSlider = document.getElementById('thresholdSlider');
            const thresholdValueSpan = document.getElementById('thresholdValue');
            if(thresholdSlider) thresholdSlider.value = 100;
            if(thresholdValueSpan) thresholdValueSpan.textContent = '100%';
            
            updateControlsState();

            const currentClusterIdsFromNewTree = new Set();
            const rootOfNewTree = d3.hierarchy(treeData);
            rootOfNewTree.leaves().forEach(leaf => {
                if (leaf.data && leaf.data.cluster_id !== undefined) {
                    currentClusterIdsFromNewTree.add(String(leaf.data.cluster_id));
                }
            });

            const newIdsForThisOperation = new Set(
                [...currentClusterIdsFromNewTree].filter(id => !previousClusterIdsBeforeRecluster.has(id))
            );
            currentNewClusterIds = newIdsForThisOperation;

            let currentLeafDisplayCount = 0;
            (function countLeaves(node) {
                if (!node || typeof node !== 'object') return;
                if ((!node.children || node.children.length === 0) && node.id !== "empty_root" && node.id !== "empty_root_no_data" && node.id !== "error_root" && node.id !== "error_scipy_tree" ) {
                    if(node.cluster_id !== undefined && node.cluster_id !== null) currentLeafDisplayCount++;
                } else if (node.children) {
                    node.children.forEach(countLeaves);
                }
            })(treeData);
            
            if (currentNewClusterIds.size > 0) {
                messageDiv.textContent = `Reclustering complete. ${currentLeafDisplayCount} leaf clusters found (${currentNewClusterIds.size} new).`;
                messageDiv.style.color = '#e53e3e';
                if (acknowledgeBtn) acknowledgeBtn.style.display = 'inline-block';
            } else if (previousClusterIdsBeforeRecluster.size > 0 && currentClusterIdsFromNewTree.size !== previousClusterIdsBeforeRecluster.size) {
                messageDiv.textContent = `Reclustering complete. ${currentLeafDisplayCount} leaf clusters found. Structure changed.`;
                messageDiv.style.color = '#333';
                if (acknowledgeBtn) acknowledgeBtn.style.display = 'none';
            }
            else {
                messageDiv.textContent = `Reclustering complete. ${currentLeafDisplayCount} leaf clusters found. No new clusters identified.`;
                messageDiv.style.color = '#333';
                if (acknowledgeBtn) acknowledgeBtn.style.display = 'none';
            }

            showInlineDendrogram(treeData, currentDendrogramHeight, currentNewClusterIds);
            resetInlineZoom();
            updateLegend();
            clearSidebarVisualization();

            const thresholdSliderElem = document.getElementById('thresholdSlider');
            if (thresholdSliderElem && window.lastTreeRoot) {
                requestAnimationFrame(() => { thresholdSliderElem.dispatchEvent(new Event('input')); });
            }

        } catch (err) {
            if (err.name === 'AbortError') {
                console.log("Recluster and redraw operation aborted.");
            } else {
                console.error("Error during recluster/redraw:", err);
                messageDiv.textContent = `Error: ${err.message || "Failed to recluster."}`;
                messageDiv.style.color = '#e53e3e';
                if (acknowledgeBtn) acknowledgeBtn.style.display = 'none';
                if (treeInfoSpan) treeInfoSpan.textContent = '';
                window.originalTreeData = null;
                window.lastTreeData = null;
                window.originalLeafCount = 0;
                currentNewClusterIds.clear();
                showInlineDendrogram(null, currentDendrogramHeight, currentNewClusterIds);
            }
        } finally {
            if (!globalAbortController.signal.aborted) {
                hideLoading();
            }
        }
    }

    // Function to add an item to the saved list
    function addSavedItem(item) { 
        if (savedItems.some(saved => saved.id === item.id && saved.type === item.type)) {
            console.log("Item already saved:", item);
            return;
        }
        if (savedItems.length >= MAX_SAVED_ITEMS) {
            alert(`You can save a maximum of ${MAX_SAVED_ITEMS} items. Please remove an item to save a new one.`);
            return;
        }
        savedItems.push(item);
        renderSavedItemsList();
        console.log("Saved item:", item);
    }

    // Function to remove an item from the saved list
    function removeSavedItem(itemId) {
        savedItems = savedItems.filter(item => item.id !== itemId);
        renderSavedItemsList();
        console.log("Removed item with ID:", itemId);
    }

    function handleSaveSelection() {
        if (!isSidebarOpen || !sidebarCy) {
            alert("Please open the sidebar and ensure a visualization is active.");
            return;
        }

        if (selectedSidebarNodes.size === 0) {
            alert("Please select at least one node to save its cluster information.");
            return;
        }

        const nodesByCluster = new Map();

        // Group selected nodes by their clusterID and collect details
        selectedSidebarNodes.forEach(nodeId => {
            const node = sidebarCy.getElementById(nodeId);
            if (node && node.length > 0) {
                const nodeData = node.data();
                const clusterID = String(nodeData.clusterID);
                const ipAddress = node.id(); // Assuming node ID is the IP address
                const attackTypes = nodeData.InvolvedAttackTypes || []; // Get from node data

                if (!nodesByCluster.has(clusterID)) {
                    nodesByCluster.set(clusterID, []);
                }
                nodesByCluster.get(clusterID).push({
                    ip: ipAddress,
                    attackTypes: attackTypes
                });
            }
        });

        if (nodesByCluster.size === 0) {
            alert("Could not retrieve details for selected nodes.");
            return;
        }

        let itemsProcessedCount = 0; // To track if anything was saved or updated

        nodesByCluster.forEach((newlySelectedNodeDetailsList, clusterID) => {
            const existingSavedItemIndex = savedItems.findIndex(item => item.id === clusterID && item.type === 'cluster-with-details');

            if (existingSavedItemIndex !== -1) {
                // --- ITEM EXISTS, UPDATE IT ---
                const existingItem = savedItems[existingSavedItemIndex];
                let updated = false;

                newlySelectedNodeDetailsList.forEach(newNodeDetail => {
                    // Check if this specific node (by IP) is already in the saved details for this cluster
                    const alreadySelected = existingItem.data.selectedNodesDetails.some(existingNode => existingNode.ip === newNodeDetail.ip);
                    if (!alreadySelected) {
                        existingItem.data.selectedNodesDetails.push(newNodeDetail);
                        updated = true;
                    }
                });

                if (updated) {
                    // Rebuild displayDescriptions based on the potentially updated selectedNodesDetails
                    existingItem.data.displayDescriptions = existingItem.data.selectedNodesDetails.map(detail => {
                        let desc = `IP: ${detail.ip}`;
                        if (detail.attackTypes && detail.attackTypes.length > 0 && detail.attackTypes.join('') !== "N/A") {
                            desc += ` (Attacks: ${detail.attackTypes.join(', ')})`;
                        }
                        return desc;
                    });
                    console.log(`Updated existing saved item for Cluster ${clusterID}:`, existingItem);
                    itemsProcessedCount++;
                } else {
                    console.log(`No new nodes to add to existing saved item for Cluster ${clusterID}. All selected nodes were already present.`);
                }

            } else {
                // --- ITEM DOES NOT EXIST, ADD NEW ---
                if (savedItems.length >= MAX_SAVED_ITEMS) {
                    alert(`Cannot save Cluster ${clusterID}. Maximum of ${MAX_SAVED_ITEMS} items reached. Please remove an item to save a new one.`);
                    return; // Skip processing this cluster if max is reached
                }

                const displayDescriptions = newlySelectedNodeDetailsList.map(detail => {
                    let desc = `IP: ${detail.ip}`;
                    if (detail.attackTypes && detail.attackTypes.length > 0 && detail.attackTypes.join('') !== "N/A") {
                        desc += ` (Attacks: ${detail.attackTypes.join(', ')})`;
                    }
                    return desc;
                });

                const newItem = {
                    id: clusterID, // Use clusterID as the unique ID for this saved item
                    type: 'cluster-with-details', // New type
                    name: `Cluster ${clusterID}`,
                    data: {
                        clusterId: clusterID,
                        // Store the original selected IPs and their full descriptions for display
                        selectedNodesDetails: newlySelectedNodeDetailsList, // This is a fresh list for a new item
                        displayDescriptions: displayDescriptions // For easy rendering in the list
                    }
                };
                savedItems.push(newItem); // Directly add the new item to the list
                console.log(`Added new saved item for Cluster ${clusterID}:`, newItem);
                itemsProcessedCount++;
            }
        });

        if (itemsProcessedCount > 0) {
            renderSavedItemsList(); // Re-render the list if any item was added or updated
            console.log(`${itemsProcessedCount} cluster(s)/group(s) processed (saved or updated) with node details.`);

            // Clear current node selections after saving
            if (sidebarCy) {
                sidebarCy.nodes().filter(n => selectedSidebarNodes.has(n.id())).unselect().forEach(n => {
                    const originalNodeColor = n.scratch('_originalColor') || clusterHighlightColors.get(String(n.data('clusterID'))) || '#888';
                    n.style('background-color', originalNodeColor);
                });
            }
            selectedSidebarNodes.clear();
            updateSidebarTableForSelectedNodesAndEdges(); // Revert table to broader context if needed
        } else {
            // This case can occur if the save limit was hit before processing any cluster,
            // or if all selected nodes were already present in existing saved items and no new items could be added.
            alert("No new information was saved. Selected nodes might already be part of saved items, or the save limit was reached for new entries.");
        }
    }

    async function fetchAndRenderLouvainIpGraph() {
        const graphLoadingIndicator = document.getElementById('packetSimilarityLoading');
        const graphContainerDiv = document.getElementById('louvain-ip-graph-container');
        const ipGraphLayoutSelect = document.getElementById('ipGraphLayoutSelect');

        if (!graphLoadingIndicator || !graphContainerDiv) {
            console.error("Required HTML elements for IP graph are missing.");
            return;
        }

        showLoading();
        graphLoadingIndicator.style.display = 'flex';

        if (window.louvainIpCy) {
            window.louvainIpCy.destroy();
            window.louvainIpCy = null;
        }
        graphContainerDiv.innerHTML = '';

        try {
            const response = await fetch(`${API_BASE_URL}/louvain_ip_graph_data`, { signal: globalAbortController.signal });

            if (globalAbortController.signal.aborted) {
                throw new DOMException("Operation aborted by user.", "AbortError");
            }

            if (!response.ok) {
                const errData = await response.json().catch(() => ({ error: "Failed to fetch Louvain IP graph data." }));
                throw new Error(errData.error || `HTTP error ${response.status}`);
            }
            const graphData = await response.json();

            if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
                graphContainerDiv.innerHTML = '<p style="text-align:center; padding-top:50px;">No IP graph data to display.</p>';
                return;
            }
            
            window.louvainIpCy = cytoscape({
                container: graphContainerDiv,
                elements: {
                    nodes: graphData.nodes,
                    edges: graphData.edges
                },
                style: [ // Using the simplified style from the previous step
                    {
                        selector: 'node',
                        style: {
                            'background-color': 'data(node_color)', 
                            'width': 25, 
                            'height': 25, 
                            'shape': 'ellipse'
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'line-color': '#888', 
                            'width': 2
                        }
                    }
                ],
                layout: {
                    name: 'preset',
                    fit: true,
                    padding: 50,
                    animate: false
                },
                minZoom: 0.05,
                maxZoom: 5,
                wheelSensitivity: 0.2,
                autoungrabify: true, 
            });
            
            window.louvainIpCy.fit(undefined, 50);

            const tooltip = d3.select("#tooltip");

            window.louvainIpCy.removeListener('mouseover mouseout click'); 

            window.louvainIpCy.on('mouseover', 'node', (event) => {
                const el = event.target;
                const data = el.data();

                let content = `<b>IP:</b> ${data.label || data.id}`; 
                if (data.is_attacker) {
                    content += ` <strong style="color:#FF3333;">(Attacker)</strong>`;
                }
                content += `<br><b>Community:</b> ${data.clusterId || 'N/A'}`;
                if (data.is_community_anomalous && !data.is_attacker) {
                    content += ` <strong style="color:orange;">(In Anomalous Community)</strong>`;
                }
                content += `<br><b>Class:</b> ${data.classification || 'N/A'}`;
                content += `<br><b>Total Pkts (Graph):</b> ${data.packet_count || 0}`;

                if (data.features_for_pca) {
                    content += `<br>--- PCA Input Features ---`;
                    content += `<br>Outgoing Pkts: ${data.features_for_pca.outgoing_packets}`;
                    content += `<br>Incoming Pkts: ${data.features_for_pca.incoming_packets}`;
                    content += `<br>Outgoing Bytes: ${data.features_for_pca.outgoing_bytes}`;
                    content += `<br>Incoming Bytes: ${data.features_for_pca.incoming_bytes}`;
                    content += `<br>Distinct Dests: ${data.features_for_pca.distinct_destinations}`;
                    content += `<br>Distinct Srcs (contacted by): ${data.features_for_pca.distinct_sources_contacted_by}`;
                    content += `<br>Src Sessions: ${data.features_for_pca.source_sessions}`;
                    content += `<br>Dest Sessions: ${data.features_for_pca.destination_sessions}`;
                }
                
                if (content && event.originalEvent) { 
                    tooltip.html(content).style("display", "block")
                        .style("left", (event.originalEvent.pageX + 10) + "px")
                        .style("top", (event.originalEvent.pageY - 15) + "px");
                } else if (content && event.renderedPosition) { 
                     const graphContainerRect = graphContainerDiv.getBoundingClientRect();
                     tooltip.html(content).style("display", "block")
                        .style("left", (graphContainerRect.left + event.renderedPosition.x + window.scrollX + 10) + "px")
                        .style("top", (graphContainerRect.top + event.renderedPosition.y + window.scrollY - 15) + "px");
                } else {
                    tooltip.style("display", "none");
                }
            });
            
            window.louvainIpCy.on('mouseover', 'edge', (event) => {
                const el = event.target;
                const data = el.data();
                let content = `<b>Source:</b> ${data.source}`;
                content += `<br><b>Target:</b> ${data.target}`;
                content += `<br><b>Packets:</b> ${data.packet_count || 0}`;
                content += `<br><b>Total Bytes:</b> ${data.total_length || 0}`;
                 if (content && event.originalEvent) { 
                    tooltip.html(content).style("display", "block")
                        .style("left", (event.originalEvent.pageX + 10) + "px")
                        .style("top", (event.originalEvent.pageY - 15) + "px");
                } else if (content && event.renderedPosition) {
                     const graphContainerRect = graphContainerDiv.getBoundingClientRect();
                     tooltip.html(content).style("display", "block")
                        .style("left", (graphContainerRect.left + event.renderedPosition.x + window.scrollX + 10) + "px")
                        .style("top", (graphContainerRect.top + event.renderedPosition.y + window.scrollY - 15) + "px");
                } else {
                    tooltip.style("display", "none");
                }
            });

            window.louvainIpCy.on('mouseout', 'node, edge', (event) => { 
                tooltip.style("display", "none");
            });

            window.louvainIpCy.on('click', 'node', function(event) {
                const node = event.target;
                if (window.sidebarCy) {
                    const sidebarNode = window.sidebarCy.getElementById(node.id());
                    if (sidebarNode.length > 0) {
                        toggleSidebar(true);
                        sidebarNode.trigger('click');
                        window.sidebarCy.animate({ fit: { eles: sidebarNode, padding: 100 } }, { duration: 400 });
                    } else {
                        const clusterToLoad = node.data('clusterId');
                        if (clusterToLoad && clusterToLoad !== 'N/A') {
                            let highlightColor = clusterHighlightColors.get(clusterToLoad);
                            if (!highlightColor) {
                                highlightColor = generateUniqueHighlightColor();
                                clusterHighlightColors.set(clusterToLoad, highlightColor);
                            }
                            const isAnomalousCommunity = node.data('is_community_anomalous') || false;
                            visualizeClusterInSidebar(clusterToLoad, highlightColor, isAnomalousCommunity)
                                .then(() => {
                                    const newlyAddedNodeInSidebar = window.sidebarCy.getElementById(node.id());
                                    if(newlyAddedNodeInSidebar && newlyAddedNodeInSidebar.length > 0){
                                       newlyAddedNodeInSidebar.trigger('click');
                                       window.sidebarCy.animate({ fit: { eles: newlyAddedNodeInSidebar, padding: 100 } }, { duration: 400 });
                                    }
                                });
                            highlightTreeClusters(new Set(clusterHighlightColors.keys()));
                        }
                    }
                }
            });
            if (ipGraphLayoutSelect && ipGraphLayoutSelect.value !== 'preset') {
                ipGraphLayoutSelect.value = 'preset';
            }

        } catch (error) {
            if (error.name === 'AbortError') {
                console.log("Louvain IP graph loading aborted by user.");
                graphContainerDiv.innerHTML = `<p style="text-align:center; padding-top:50px;">Operation Cancelled by user.</p>`;
            } else {
                console.error("Error fetching/rendering Louvain IP graph:", error);
                graphContainerDiv.innerHTML = `<p style="text-align:center; padding-top:50px;">Error loading IP Graph: ${error.message}</p>`;
            }
        } finally {
            graphLoadingIndicator.style.display = 'none';
            if (!globalAbortController.signal.aborted) {
                hideLoading();
            }
        }
    }

    async function fetchAndRenderSankeyDiagram() {
        const sankeyContainer = d3.select("#sankey-diagram-container");
        const loadingIndicator = document.getElementById('sankeyLoading');

        if (!sankeyContainer.node()) {
            console.error("Sankey container not found.");
            if(loadingIndicator) loadingIndicator.style.display = 'none';
            return;
        }
        sankeyContainer.html(""); 
        if(loadingIndicator) loadingIndicator.style.display = 'flex';
        sankeyDiagramRendered = false;

        let activeDimensions = []; 
        window.currentSankeyDimensionsOrder.forEach(dimDefinition => {
            const checkbox = document.getElementById(`sankey_dim_cb_${dimDefinition.value}`);
            if (checkbox && checkbox.checked) {
                activeDimensions.push(dimDefinition.value); 
            }
        });

        if (activeDimensions.length < 2) {
            alert("Please select at least two dimensions for the Sankey diagram.");
            if(loadingIndicator) loadingIndicator.style.display = 'none';
            sankeyContainer.html("<p style='color:red; text-align:center; padding-top: 50px;'>Error: Please select at least two dimensions.</p>");
            return;
        }

        try {
            const payload = {
                dimensions: activeDimensions,
                sankey_filter: window.activeSankeyFilter // Pass the active filter to the backend
            };

            // Also pass the main time filter if it's set
            if (window.lastAppliedTimeSelection && window.lastAppliedTimeSelection.startTime) {
                payload.start_time = window.lastAppliedTimeSelection.startTime.toISOString();
                payload.end_time = window.lastAppliedTimeSelection.endTime.toISOString();
            }

            const response = await fetch(`${API_BASE_URL}/sankey_data`, {
                method: 'POST', // Use POST to send the filter payload
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({error: `HTTP error ${response.status}`}));
                throw new Error(errData.error || `Failed to fetch Sankey data.`);
            }
            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }
            if (!data.nodes || data.nodes.length === 0 || !data.links || data.links.length === 0) {
                sankeyContainer.html("<p style='text-align:center; padding-top:50px;'>No data available for the selected Sankey dimensions.</p>");
                sankeyDiagramRendered = false; 
                if(loadingIndicator) loadingIndicator.style.display = 'none';
                return;
            }

            renderSankey(data, "#sankey-diagram-container", activeDimensions); 
            sankeyDiagramRendered = true;

        } catch (error) {
            console.error("Error fetching or rendering Sankey diagram:", error);
            sankeyContainer.html(`<p style='color:red; text-align:center; padding-top: 50px;'>Error: ${error.message}</p>`);
            sankeyDiagramRendered = false;
        } finally {
            if(loadingIndicator) loadingIndicator.style.display = 'none';
        }
    }

    function renderSankey(data, containerSelector, activeDimensions) {
        const container = d3.select(containerSelector);
        const containerNode = container.node();
        if (!containerNode) {
            console.error("Sankey container node not found in renderSankey.");
            return;
        }
        container.selectAll("svg").remove();

        const containerRect = containerNode.getBoundingClientRect();
        const margin = {top: 30, right: 200, bottom: 30, left: 200};

        const svgWidth = containerRect.width > 0 ? containerRect.width : 800;
        const svgHeight = containerRect.height > 0 ? containerRect.height : 700;

        const width = svgWidth - margin.left - margin.right;
        const height = svgHeight - margin.top - margin.bottom;

        if (width <= 0 || height <= 0) {
            container.html("<p style='text-align:center; color:orange; padding-top:50px;'>Cannot render Sankey: container too small or not visible.</p>");
            return;
        }

        const svg = container.append("svg")
            .attr("width", svgWidth)
            .attr("height", svgHeight)
            .style("font", "10px sans-serif")
            .on("click", function(event) { // Click on background clears filter
                if (event.target === this) {
                    window.activeSankeyFilter = null;
                    window.activeSankeyNodeFilter = null; // Also clear the node filter
                    const applyBtn = document.getElementById('applySankeyToHeatmapBtn');
                    if (applyBtn) {
                        applyBtn.disabled = true;
                    }
                    fetchAndRenderSankeyDiagram();
                }
            })
        .append("g")
            .attr("transform", `translate(${margin.left},${margin.top})`);
            
        const sankeyLayout = d3.sankey()
            .nodeId(d_node => d_node.node)
            .nodeAlign(d3.sankeyJustify)
            .nodeWidth(20).nodePadding(12)
            .extent([[1, 5], [width - 1, height - 5]]);

        const {nodes, links} = sankeyLayout(data);

        // Calculate the filtered value for each node for dimming purposes
        nodes.forEach(node => {
            const incomingFiltered = d3.sum(node.targetLinks, l => l.filtered_value || 0);
            const outgoingFiltered = d3.sum(node.sourceLinks, l => l.filtered_value || 0);
            node.filtered_value = Math.max(incomingFiltered, outgoingFiltered);
        });

        const colorScale = d3.scaleOrdinal(d3.schemeCategory10);
        nodes.forEach(node => { node.color = colorScale(node.name.split(":")[0]); });

        const linkGroups = svg.append("g").attr("class", "links").attr("fill", "none")
            .selectAll("g").data(links).join("g")
            .attr("class", "link")
            .style("mix-blend-mode", "multiply");

        // 1. Background Path: Represents the TOTAL value of the link
        linkGroups.append("path")
            .attr("d", d3.sankeyLinkHorizontal())
            .attr("stroke", "#e0e0e0") // Always light gray
            .attr("stroke-width", d_link => Math.max(1.5, d_link.width));

        // 2. Foreground Path: Represents the FILTERED portion of the link
        linkGroups.append("path")
            .attr("d", d3.sankeyLinkHorizontal())
            .attr("stroke", d_link => d_link.source.color)
            .attr("stroke-opacity", 0.8)
            .attr("stroke-width", d_link => {
                const MIN_HIGHLIGHT_WIDTH = 1.5;
                const EPSILON = 1e-9; // A very small number to treat as zero

                // If total value is zero or filtered value is effectively zero, draw nothing.
                if (d_link.value <= EPSILON || !d_link.filtered_value || d_link.filtered_value <= EPSILON) {
                    return 0;
                }

                const totalWidth = Math.max(1.5, d_link.width);
                const ratio = d_link.filtered_value / d_link.value;
                let highlightWidth = totalWidth * ratio;

                // If the highlight is tiny but non-zero, enforce the minimum width.
                if (highlightWidth > 0 && highlightWidth < MIN_HIGHLIGHT_WIDTH) {
                    highlightWidth = MIN_HIGHLIGHT_WIDTH;
                }

                // Ensure the highlight never exceeds the total width of the link.
                return Math.min(highlightWidth, totalWidth);
            });

        // Add a tooltip to the link group showing both values
        linkGroups.append("title").text(d_title => 
            `${d_title.source.name} \u2192 ${d_title.target.name}\n` +
            `Total Value: ${d_title.value.toLocaleString()}\n` +
            `Selected Value: ${(d_title.filtered_value || 0).toLocaleString()}`
        );

        const nodeClickHandler = function(event, d_node_clicked) {
            event.stopPropagation();
            
            // If clicking the same node, clear the filter. Otherwise, set a new one.
            if (window.activeSankeyNodeFilter && window.activeSankeyNodeFilter.label === d_node_clicked.name) {
                window.activeSankeyNodeFilter = null;
                window.activeSankeyFilter = null;
            } else {
                const [dimensionLabel, ...valueParts] = d_node_clicked.name.split(': ');
                const value = valueParts.join(': ');
                const dimensionKey = (DEFAULT_SANKEY_DIMENSIONS.find(d => d.label === dimensionLabel) || {}).value;

                if (dimensionKey) {
                    const newFilter = {
                        dimensionKey: dimensionKey,
                        value: value,
                        label: d_node_clicked.name
                    };
                    window.activeSankeyNodeFilter = newFilter;
                    window.activeSankeyFilter = newFilter; // Also set the visual filter
                } else {
                    console.error("Could not find dimension key for label:", dimensionLabel);
                    window.activeSankeyNodeFilter = null;
                    window.activeSankeyFilter = null;
                }
            }
            
            const applyBtn = document.getElementById('applySankeyToHeatmapBtn');
            if (applyBtn) {
                applyBtn.disabled = !window.activeSankeyNodeFilter;
            }

            // Re-fetch and re-render the entire Sankey with the new filter context
            fetchAndRenderSankeyDiagram();
        };

        const nodeGroup = svg.append("g").selectAll("g.node-group").data(nodes).join("g")
            .attr("class", "node-group")
            .attr("transform", d_node => `translate(${d_node.x0}, ${d_node.y0})`)
            .style("opacity", d => (d.filtered_value > 0 || !window.activeSankeyFilter) ? 1.0 : 0.3) // Dim nodes not in selection
            .on("click", nodeClickHandler);

        // Draw a single rectangle for each node, no splitting.
        nodeGroup.append("rect")
            .attr("height", d => Math.max(1, d.y1 - d.y0))
            .attr("width", d => d.x1 - d.x0)
            .attr("fill", d => d.color)
            .attr("stroke", "#333")
            .attr("stroke-width", 0.5)
            .append("title").text(d_title => 
                `${d_title.name}\n` +
                `Total Value: ${d_title.value.toLocaleString()}\n`+
                `Selected Value: ${(d_title.filtered_value || 0).toLocaleString()}`
            );

        nodeGroup.append("text")
            .attr("x", d_node => d_node.x0 < width / 2 ? (d_node.x1 - d_node.x0 + 8) : -8)
            .attr("y", d_node => (d_node.y1 - d_node.y0) / 2)
            .attr("dy", "0.35em").attr("text-anchor", d_node => d_node.x0 < width / 2 ? "start" : "end")
            .style("font-size", "11px").style("fill", "#000").style("pointer-events", "none")
            .text(d_node => { const MAX_LABEL_LENGTH = 30; return d_node.name.length > MAX_LABEL_LENGTH ? d_node.name.substring(0, MAX_LABEL_LENGTH - 3) + "..." : d_node.name; });
    }

    async function updateMainViewAfterSankeyFilter() {
        console.log("Updating main view due to Sankey filter change. Current filter:", window.activeSankeyNodeFilter);
        showLoading();
        try {
            window.sankeyMatchingClusterIds.clear(); // Clear previous matches

            if (window.activeSankeyNodeFilter) {
                console.log("Active Sankey filter detected, fetching matching cluster IDs...");
                const mainFilters = {
                    payloadKeyword: document.getElementById('payloadSearch').value.trim().toLowerCase(),
                    sourceFilter: document.getElementById('sourceFilter').value.trim().toLowerCase(),
                    destinationFilter: document.getElementById('destinationFilter').value.trim().toLowerCase(),
                    protocolFilter: document.getElementById('protocolFilter').value.trim().toLowerCase(),
                    minSourceAmt: document.getElementById('minSourceAmtFilter').value,
                    maxSourceAmt: document.getElementById('maxSourceAmtFilter').value,
                    minDestinationAmt: document.getElementById('minDestinationAmtFilter').value,
                    maxDestinationAmt: document.getElementById('maxDestinationAmtFilter').value
                };

                const response = await fetch(`${API_BASE_URL}/get_sankey_matching_clusters`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sankeyFilter: window.activeSankeyNodeFilter,
                        mainFilters: mainFilters
                    }),
                    signal: globalAbortController.signal 
                });

                if (globalAbortController.signal.aborted) {
                    throw new DOMException("Operation aborted by user.", "AbortError");
                }
                if (!response.ok) {
                    const errData = await response.json().catch(() => ({error: `HTTP error ${response.status}`}));
                    throw new Error(errData.error || `Failed to fetch Sankey matching clusters.`);
                }
                const data = await response.json();
                if (data.matchingClusterIds) {
                    window.sankeyMatchingClusterIds = new Set(data.matchingClusterIds.map(String));
                    console.log("Sankey matching cluster IDs fetched:", Array.from(window.sankeyMatchingClusterIds));
                }
            } else {
                console.log("Sankey filter is null, sankeyMatchingClusterIds cleared.");
            }
            
            if (window.lastTreeData) {
                showInlineDendrogram(window.lastTreeData, document.getElementById("inline-dendrogram-container").clientHeight, currentNewClusterIds);
            } else {
                // Fallback to a full load if for some reason there's no data to draw.
                console.warn("No tree data available. Performing a full load.");
                await updateHeatmap();
                await loadInlineDendrogram();
            }

        } catch (error) {
            if (error.name === 'AbortError') {
                console.log("Main view update after Sankey filter aborted by user.");
            } else {
                console.error("Error updating main view after Sankey filter:", error);
                alert(`Error applying Sankey filter to main view: ${error.message || 'Unknown error'}`);
            }
        } finally {
            if (!globalAbortController.signal.aborted) {
                hideLoading();
            }
        }
    }

    function moveSankeyDimension(index, direction) {
        if (direction === 'left' && index > 0) {
            // Swap with previous element
            [window.currentSankeyDimensionsOrder[index], window.currentSankeyDimensionsOrder[index - 1]] = 
            [window.currentSankeyDimensionsOrder[index - 1], window.currentSankeyDimensionsOrder[index]];
        } else if (direction === 'right' && index < window.currentSankeyDimensionsOrder.length - 1) {
            // Swap with next element
            [window.currentSankeyDimensionsOrder[index], window.currentSankeyDimensionsOrder[index + 1]] = 
            [window.currentSankeyDimensionsOrder[index + 1], window.currentSankeyDimensionsOrder[index]];
        }

        populateSankeyDimensionCheckboxes(); // Re-render the checkboxes with new order and button states

        const sankeyCard = document.getElementById('sankeyCard');
        if (sankeyCard && sankeyCard.style.display !== 'none' && sankeyCard.style.display !== '') {
            fetchAndRenderSankeyDiagram(); // Update Sankey diagram if it's visible
        }
    }

    function populateSankeyDimensionCheckboxes() {
        const container = document.getElementById('sankeyDimensionCheckboxes');
        if (!container) {
            console.error("Sankey dimension checkbox container not found.");
            return;
        }
        container.innerHTML = ''; // Clear existing

        window.currentSankeyDimensionsOrder.forEach((dim, index) => {
            const div = document.createElement('div');
            // This is the container for ONE filter option (checkbox, label, buttons)
            div.style.display = 'flex';
            div.style.alignItems = 'center';
            div.style.marginBottom = '5px';
            div.style.padding = '3px 6px'; // A little padding
            div.style.border = '1px solid #ddd'; // Border to group elements together visually
            div.style.borderRadius = '5px';
            div.style.marginRight = '8px'; // Spacing between filter groups

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `sankey_dim_cb_${dim.value}`;
            checkbox.value = dim.value;
            checkbox.checked = dim.defaultChecked;
            checkbox.setAttribute('data-label', dim.label);
            checkbox.style.marginRight = '5px';

            checkbox.addEventListener('change', () => {
                const dimInOrder = window.currentSankeyDimensionsOrder.find(d => d.value === checkbox.value);
                if (dimInOrder) {
                    dimInOrder.defaultChecked = checkbox.checked;
                }
                const sankeyCard = document.getElementById('sankeyCard');
                if (sankeyCard && sankeyCard.style.display !== 'none' && sankeyCard.style.display !== '') {
                    fetchAndRenderSankeyDiagram();
                }
            });

            const label = document.createElement('label');
            label.htmlFor = checkbox.id;
            label.textContent = dim.label;
            label.style.marginRight = '5px'; // Reduced margin
            label.style.minWidth = '110px'; 
            label.style.marginBottom = '0'; // Remove bottom margin from label

            const leftBtn = document.createElement('button');
            leftBtn.innerHTML = '&#x25C0;'; // Left arrow
            leftBtn.title = 'Move Left';
            leftBtn.style.padding = '3px 6px';
            leftBtn.style.fontSize = '12px';
            leftBtn.style.marginRight = '2px'; // Tighter spacing
            leftBtn.disabled = index === 0;
            leftBtn.onclick = (e) => { e.preventDefault(); moveSankeyDimension(index, 'left'); };

            const rightBtn = document.createElement('button');
            rightBtn.innerHTML = '&#x25B6;'; // Right arrow
            rightBtn.title = 'Move Right';
            rightBtn.style.padding = '3px 6px';
            rightBtn.style.fontSize = '12px';
            rightBtn.disabled = index === window.currentSankeyDimensionsOrder.length - 1;
            rightBtn.onclick = (e) => { e.preventDefault(); moveSankeyDimension(index, 'right'); };

            div.appendChild(checkbox);
            div.appendChild(label);
            div.appendChild(leftBtn);
            div.appendChild(rightBtn);
            container.appendChild(div);
        });
    }

    function renderSavedItemsList() {
        const listElement = document.getElementById('saved-items-list');
        const noItemsMessage = document.getElementById('no-saved-items');
        if (!listElement || !noItemsMessage) return;

        listElement.innerHTML = ''; 

        if (savedItems.length === 0) {
            noItemsMessage.style.display = 'block';
            return;
        }
        noItemsMessage.style.display = 'none';

        savedItems.forEach(item => {
            const listItem = document.createElement('li');
            listItem.style.padding = "5px 0";
            listItem.style.borderBottom = "1px solid #eee";
            listItem.setAttribute('data-id', item.id);
            listItem.setAttribute('data-type', item.type);

            const itemNameSpan = document.createElement('span');
            itemNameSpan.textContent = item.name;
            itemNameSpan.style.fontWeight = "bold";
            itemNameSpan.style.cursor = 'pointer';
            itemNameSpan.title = `Click to add/focus on ${item.name}`;
            
            listItem.appendChild(itemNameSpan);

            if (item.type === 'cluster-with-details' && item.data && item.data.displayDescriptions) {
                const detailsContainer = document.createElement('div');
                detailsContainer.style.marginLeft = "10px";
                detailsContainer.style.fontSize = "11px";
                detailsContainer.style.color = "#555";
                item.data.displayDescriptions.forEach(desc => {
                    const descP = document.createElement('p');
                    descP.style.margin = "2px 0";
                    descP.textContent = "↳ " + desc;
                    detailsContainer.appendChild(descP);
                });
                listItem.appendChild(detailsContainer);
            }
            
            const removeBtn = document.createElement('button');
            removeBtn.textContent = '✖';
            removeBtn.title = "Remove item";
            removeBtn.style.float = 'right';
            removeBtn.style.fontSize = '10px';
            removeBtn.style.padding = '1px 4px';
            removeBtn.style.marginLeft = '5px';
            removeBtn.style.backgroundColor = '#f56565';
            removeBtn.style.color = 'white';
            removeBtn.style.border = 'none';
            removeBtn.style.borderRadius = '3px';
            removeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                removeSavedItem(item.id);
            });

            listItem.appendChild(removeBtn);
            listElement.appendChild(listItem);
        });
    }

    function _renderSidebarTable(jsonData, page) {
        sidebarTableContainer.innerHTML = ''; // Clear previous content

        if (!jsonData || !jsonData.rows || jsonData.rows.length === 0) {
            sidebarTableContainer.innerHTML = '<p style="text-align: center; padding: 20px; color: #6c757d;">No results found.</p>';
            sidebarTablePagination.style.display = 'none';
            return;
        }

        const table = document.createElement('table');
        const thead = document.createElement('thead');
        const tbody = document.createElement('tbody');
        const headerRow = document.createElement('tr');

        const headers = Object.keys(jsonData.rows[0]);
        headers.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);

        const searchQuery = (document.getElementById('sidebarTableSearchInput').value || "").toLowerCase();
        const keywords = searchQuery.split(' ').filter(k => k.trim());

        jsonData.rows.forEach(rowData => {
            const tr = document.createElement('tr');
            headers.forEach(header => {
                const td = document.createElement('td');
                let cellContent = rowData[header] !== null && rowData[header] !== undefined ? String(rowData[header]) : "";
                
                if (keywords.length > 0) {
                    const regex = new RegExp(keywords.map(k => k.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')).join('|'), 'gi');
                    td.innerHTML = cellContent.replace(regex, match => `<mark>${match}</mark>`);
                } else {
                    td.textContent = cellContent;
                }
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        });

        table.appendChild(thead);
        table.appendChild(tbody);
        sidebarTableContainer.appendChild(table);
        sidebarTableContainer.style.display = 'block';

        const total = jsonData.total;
        if (total > TABLE_PAGE_SIZE) {
            sidebarTablePagination.style.display = 'block';
            const totalPages = Math.ceil(total / TABLE_PAGE_SIZE);
            document.getElementById('sidebarTotalPages').textContent = totalPages || 1;
            document.getElementById('sidebarCurrentPageInput').value = page;
            document.getElementById('sidebarCurrentPageInput').max = totalPages || 1;
        } else {
            sidebarTablePagination.style.display = 'none';
        }
    }

    function updateTimelineButtonStates() {
        const processBtn = document.getElementById('processTimelineSelectionBtn');
        const applyBtn = document.getElementById('applyTimelineBtn');
        const resetBtn = document.getElementById('resetTimelineBtn');

        if (!applyBtn || !resetBtn || !processBtn || !window.timelineXScale) return;

        const isViewInitialized = window.lastTreeData && !window.lastTreeData.no_tree;

        if (!isViewInitialized) {
            // State before initial processing is done
            applyBtn.style.display = 'none';
            resetBtn.style.display = 'inline-block'; // Changed to make reset button visible
            processBtn.style.display = 'inline-block';
            
            const brushGroup = d3.select("#timeline-container .brush");
            const selection = brushGroup.empty() ? null : d3.brushSelection(brushGroup.node());
            processBtn.disabled = !selection;

        } else {
            // State AFTER initial processing is done
            processBtn.style.display = 'none';
            applyBtn.style.display = 'inline-block';
            resetBtn.style.display = 'inline-block';

            const fullDomain = window.timelineXScale.domain();
            const currentSelection = window.currentTimeSelection;
            const appliedSelection = window.lastAppliedTimeSelection;

            if (!currentSelection || !appliedSelection) {
                applyBtn.disabled = true;
                resetBtn.disabled = true;
                return;
            }

            const currentIsDifferentFromApplied = Math.abs(currentSelection.startTime.valueOf() - appliedSelection.startTime.valueOf()) > 1 ||
                                                Math.abs(currentSelection.endTime.valueOf() - appliedSelection.endTime.valueOf()) > 1;
            
            const appliedIsDifferentFromFull = Math.abs(appliedSelection.startTime.valueOf() - fullDomain[0].valueOf()) > 1 ||
                                                Math.abs(appliedSelection.endTime.valueOf() - fullDomain[1].valueOf()) > 1;

            applyBtn.disabled = !currentIsDifferentFromApplied;
            resetBtn.disabled = !appliedIsDifferentFromFull;
        }
    }

    async function drawTimeline() {
        const timelineCard = document.getElementById('timeline-card');
        const timelineContainer = document.getElementById('timeline-container');

        if (!timelineCard || !timelineContainer) {
            console.error("Timeline container or card not found.");
            return;
        }

        // If data is already cached, just render it and exit. The 'Apply' button listener
        // handles clearing this cache to force a refetch.
        if (window.fullTimelineData) {
            _renderTimelineFromData(window.fullTimelineData);
            return;
        }

        try {
            let url = new URL(`${API_BASE_URL}/timeline_data`);
            const granularityInput = document.getElementById('timelineGranularityInput');
            const granularityMs = granularityInput ? parseInt(granularityInput.value, 10) : null;
            
            // Append granularity parameter to the URL if it's a valid positive number
            if (granularityMs && !isNaN(granularityMs) && granularityMs > 0) {
                url.searchParams.append('interval_ms', granularityMs);
            }

            const timelineResponse = await fetch(url);
            if (!timelineResponse.ok) throw new Error(`HTTP error ${timelineResponse.status}`);
            let data = await timelineResponse.json();

            if (!data || data.length === 0) {
                timelineCard.style.display = 'none';
                return;
            }

            // Process and cache the data
            const parseDate = d3.isoParse;
            data.forEach(d => {
                d.time = parseDate(d.time);
                d.endTime = d.endTime ? parseDate(d.endTime) : null;
                d.value = +d.value;
            });
            window.fullTimelineData = data;

            // Render the timeline with the newly fetched data
            _renderTimelineFromData(data);

        } catch (error) {
            console.error("Error drawing timeline:", error);
            timelineCard.style.display = 'none';
        }
    }

    function handleBackToMainTree() {
        if (mainTreeViewBeforeSubtree) {
            isSubtreeViewActive = false;
            
            // Clear selections from the subtree view
            clearSidebarVisualization();

            // Restore the main tree view
            showInlineDendrogram(mainTreeViewBeforeSubtree, document.getElementById("inline-dendrogram-container").clientHeight);
            mainTreeViewBeforeSubtree = null; // Clear the saved state

            // Update UI state back to main view
            document.getElementById('treeControls').style.display = 'flex';
            document.getElementById('backToMainTreeBtn').style.display = 'none';
            updateSubtreeButtonState(); // Check if the create button should be re-enabled
        } else {
            // Fallback: If something went wrong, just load the original tree from scratch
            isSubtreeViewActive = false;
            loadInlineDendrogram();
            document.getElementById('treeControls').style.display = 'flex';
            document.getElementById('backToMainTreeBtn').style.display = 'none';
        }
    }

    async function updateAllVisualizations() {
        showLoading();
        try {
            globalAbortController = new AbortController(); // Use a new controller for this operation
            console.log("Applying new time filter to visualizations...");

            if (!window.currentTimeSelection) {
                throw new Error("Cannot apply filter: No time window selected.");
            }

            // The current brush selection now becomes the officially applied filter
            window.lastAppliedTimeSelection = { ...window.currentTimeSelection };

            // Re-run the main data-fetching sequence. The backend endpoints will
            // use the new time parameters from the API calls to filter the data.
            await updateHeatmap();
            if (globalAbortController.signal.aborted) throw new DOMException("Aborted");
            
            await loadInlineDendrogram();
            if (globalAbortController.signal.aborted) throw new DOMException("Aborted");
            
            // If other views are visible, update them as well.
            const sankeyCard = document.getElementById('sankeyCard');
            if (sankeyCard && sankeyCard.style.display !== 'none') {
                await fetchAndRenderSankeyDiagram();
            }

            const ipGraphCard = document.getElementById('packetSimilarityCard');
            if (ipGraphCard && ipGraphCard.style.display !== 'none') {
                await fetchAndRenderLouvainIpGraph();
            }
            
            updateLegend();
            clearSidebarVisualization();

            console.log("All visualizations updated for the new time window.");

        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error("Error updating visualizations for new time range:", error);
                alert(`An error occurred while updating the view: ${error.message}`);
            }
        } finally {
            updateTimelineButtonStates(); // Update button states after the operation
            hideLoading();
        }
    }

    function _renderTimelineFromData(data) {
        const timelineCard = document.getElementById('timeline-card');
        const timelineContainer = document.getElementById('timeline-container');
        const tooltip = d3.select("#tooltip");

        timelineContainer.innerHTML = '';
        timelineCard.style.display = 'block';

        const originalBlue = "#a0aec0";
        const originalOrange = "orange";

        const margin = { top: 10, right: 30, bottom: 40, left: 50 };
        const width = timelineContainer.clientWidth - margin.left - margin.right;
        const height = 100 - margin.top - margin.bottom;

        const svg = d3.select(timelineContainer).append("svg")
            .attr("viewBox", `0 0 ${width + margin.left + margin.right} ${height + margin.top + margin.bottom}`)
            .attr("preserveAspectRatio", "xMinYMid meet")
            .style("width", "100%").style("height", "100%");

        const context = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
        const x = d3.scaleTime().range([0, width]);
        const y = d3.scaleLinear().range([height, 0]);
        const yMax = d3.max(data, d => d.value) || 1;

        if (data.length > 0) {
            const lastEndTime = data[data.length - 1].endTime;
            x.domain([data[0].time, lastEndTime]);
        }
        y.domain([0, yMax * 1.1]);
        window.timelineXScale = x;

        context.selectAll(".bar")
            .data(data)
            .enter().append("rect")
            .attr("class", "bar")
            .attr("shape-rendering", "crispEdges")
            .attr("x", d => x(d.time))
            .attr("y", d => y(d.value))
            .attr("width", d => d.endTime ? (x(d.endTime) - x(d.time)) : 0)
            .attr("height", d => height - y(d.value))
            .attr("fill", d => d.isAttack ? originalOrange : originalBlue);
        
        if (window.lastAppliedTimeSelection) {
            const domain = x.domain();
            const start = window.lastAppliedTimeSelection.startTime;
            const end = window.lastAppliedTimeSelection.endTime;
            if (start >= domain[0] && end <= domain[1]) {
                context.append("rect")
                    .attr("class", "processed-time-overlay")
                    .attr("x", x(start))
                    .attr("y", 0)
                    .attr("width", x(end) - x(start))
                    .attr("height", height);
            }
        }

        context.append("g").attr("class", "axis axis--x").attr("transform", `translate(0,${height})`).call(d3.axisBottom(x));
        context.append("g").attr("class", "axis axis--y").call(d3.axisLeft(y).ticks(4).tickFormat(d3.format(".2s")));

        context.append("text").attr("transform", "rotate(-90)").attr("y", 0 - margin.left).attr("x", 0 - (height / 2)).attr("dy", "1em").style("text-anchor", "middle").style("font-size", "12px").style("fill", "#333").style("font-weight", "500").text("Packets");
        
        const timeFormatAxis = d3.timeFormat("%Y-%m-%d %H:%M:%S");
        const [startDate, endDate] = x.domain();
        context.append("text").attr("x", 0).attr("y", height + margin.bottom - 10).attr("text-anchor", "start").style("font-size", "11px").style("fill", "#333").style("font-weight", "500").text(`Start: ${timeFormatAxis(startDate)}`);
        context.append("text").attr("x", width).attr("y", height + margin.bottom - 10).attr("text-anchor", "end").style("font-size", "11px").style("fill", "#333").style("font-weight", "500").text(`End: ${timeFormatAxis(endDate)}`);
        
        const brushGroup = context.append("g").attr("class", "brush");

        function brushended(event) {
            if (!event.sourceEvent) return; 

            const selection = event.selection;
            if (!selection) {
                window.currentTimeSelection = null;
            } else {
                const [x0, x1] = selection.map(x.invert);
                window.currentTimeSelection = { startTime: x0, endTime: x1 };
                updateManualTimeInputs(x0, x1);
                if (document.getElementById('manualStartTime')) document.getElementById('manualStartTime').disabled = false;
                if (document.getElementById('manualEndTime')) document.getElementById('manualEndTime').disabled = false;
            }
            disableManualApplyButton();
            updateTimelineButtonStates();
        }

        function brushing(event) {
            tooltip.style("display", "none");
            if (!event.sourceEvent || !event.selection) return;

            if (!event.sourceEvent.ctrlKey) {
                const [x0_pix, x1_pix] = event.selection;
                window.currentTimeSelection = { startTime: x.invert(x0_pix), endTime: x.invert(x1_pix) };
                return; 
            }

            const [x0_pix, x1_pix] = event.selection;
            const pointer_pix = d3.pointer(event.sourceEvent, context.node())[0];

            let closestTime = null;
            let minDiff = Infinity;

            data.forEach(d => {
                const diffStart = Math.abs(pointer_pix - x(d.time));
                if (diffStart < minDiff) {
                    minDiff = diffStart;
                    closestTime = d.time;
                }
                if (d.endTime) {
                    const diffEnd = Math.abs(pointer_pix - x(d.endTime));
                    if (diffEnd < minDiff) {
                        minDiff = diffEnd;
                        closestTime = d.endTime;
                    }
                }
            });

            if (closestTime === null) return;
            const snap_pix = x(closestTime);
            const draggingStart = Math.abs(pointer_pix - x0_pix) < Math.abs(pointer_pix - x1_pix);
            
            if (draggingStart && snap_pix < x1_pix) {
                d3.select(this).call(event.target.move, [snap_pix, x1_pix]);
            } else if (!draggingStart && snap_pix > x0_pix) {
                d3.select(this).call(event.target.move, [x0_pix, snap_pix]);
            }
        }

        const brush = d3.brushX()
            .extent([[0, 0], [width, height]])
            .filter(event => !event.button)
            .on("brush", brushing)
            .on("end", brushended);

        brushGroup.call(brush);
        window.timelineBrush = brush;
        
        const initialSelection = window.lastAppliedTimeSelection || { startTime: x.domain()[0], endTime: x.domain()[1] };
        const initialBrushRange = [x(initialSelection.startTime), x(initialSelection.endTime)];
        brushGroup.call(brush.move, initialBrushRange);

        if (!d3.brushSelection(brushGroup.node())) {
            brushGroup.call(brush.move, initialBrushRange);
        }
        window.currentTimeSelection = initialSelection;
        updateManualTimeInputs(initialSelection.startTime, initialSelection.endTime);
        
        updateTimelineButtonStates();

        const bisector = d3.bisector(d => d.time).left;

        svg.on("mousemove", function(event) {
            if (!data || data.length === 0) return;

            const [mx, my] = d3.pointer(event, this);
            const mouseDate = x.invert(mx - margin.left);
            const index = bisector(data, mouseDate, 1);
            const d = data[index - 1];

            if (d && mx >= margin.left && mx <= width + margin.left && my >= margin.top && my <= height + margin.top) {
                const timeFormat = d3.timeFormat("%H:%M:%S");
                let tooltipHtml = `<strong>Time:</strong> ${timeFormat(d.time)} - ${timeFormat(d.endTime)}<br>`;
                tooltipHtml += `<strong>Total Packets:</strong> ${d.value.toLocaleString()}<br>`;
                tooltipHtml += `<strong>Status:</strong> <span style="color:${d.isAttack ? 'orange' : 'green'};">${d.isAttack ? 'Attack Detected' : 'Normal'}</span>`;

                if (d.isAttack && d.attackDetails && d.attackDetails.length > 0) {
                    const attackEntriesHtml = d.attackDetails
                        .map(attack => `<li>${attack.AttackType}: ${attack.Source}</li>`)
                        .join('');
                    tooltipHtml += `<ul style="margin: 2px 0 0 15px; padding: 0;">${attackEntriesHtml}</ul>`;
                }

                if (d.topSources && Object.keys(d.topSources).length > 0) {
                    tooltipHtml += `<hr style="margin: 4px 0;"><strong>Top Sources:</strong>`;
                    const sourcesHtml = Object.entries(d.topSources)
                        .map(([ip, count]) => `<li>${ip} (${count.toLocaleString()} pkts)</li>`)
                        .join('');
                    tooltipHtml += `<ul style="margin: 2px 0 0 15px; padding: 0;">${sourcesHtml}</ul>`;
                }
                
                tooltip.html(tooltipHtml).style("display", "block");

                const tooltipNode = tooltip.node();
                const tooltipWidth = tooltipNode.offsetWidth;
                let left = event.pageX + 15;
                if (left + tooltipWidth > window.innerWidth) {
                    left = event.pageX - tooltipWidth - 15;
                }
                tooltip.style("left", left + "px").style("top", (event.pageY - 28) + "px");
            } else {
                tooltip.style("display", "none");
            }
        });

        svg.on("mouseleave", function() {
            tooltip.style("display", "none");
        });
    }

    async function initializeAndLoadVisuals(startTime, endTime) {
        showLoading();
        try {
            globalAbortController = new AbortController();

            const initResponse = await fetch(`${API_BASE_URL}/initialize_main_view`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    start_time: startTime,
                    end_time: endTime,
                }),
                signal: globalAbortController.signal
            });

            if (globalAbortController.signal.aborted) throw new DOMException("Aborted");
            if (!initResponse.ok) {
                const errText = await initResponse.text();
                throw new Error(`Failed to initialize main view: ${errText}`);
            }
            console.log("Main view initialized by backend for the selected time range.");
            
            window.lastAppliedTimeSelection = { startTime: new Date(startTime), endTime: new Date(endTime) };

            await updateHeatmap();
            await updateTimeInfoDisplay();
            await loadInlineDendrogram();
            
            // This call now efficiently uses the cache
            await drawTimeline(); 
            
            const timelineCard = document.getElementById('timeline-card');
            const toggleTimelineBtn = document.getElementById('toggleTimelineBtn');
            if (timelineCard) timelineCard.style.display = 'none';
            if (toggleTimelineBtn) {
                toggleTimelineBtn.textContent = 'Show Timeline';
                toggleTimelineBtn.style.display = 'inline-block';
            }

            updateControlsState();
            updateRowOrderSelectState();
            updateLegend();
            
            document.getElementById('mainFilterGroup').style.display = 'block';
            document.getElementById('showSankeyBtn').style.display = 'inline-block';
            document.getElementById('sidebar-toggle').style.display = 'block';

        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error("Error during data processing and visualization:", error);
                alert(`Error processing data: ${error.message}`);
            }
        } finally {
            if (!globalAbortController.signal.aborted) {
                hideLoading();
            }
        }
    }

    async function handleSuccessfulFileLoad(responseData) {
        console.log("File loaded on backend. Resetting UI for new file.", responseData);

        document.getElementById('mainFilterGroup').style.display = 'none';
        document.getElementById('dendrogramCard').style.display = 'none';
        document.getElementById('packetSimilarityCard').style.display = 'none';
        document.getElementById('sankeyCard').style.display = 'none';
        document.getElementById('downloadProcessedDataBtn').style.display = 'none';
        
        const showSankeyBtn = document.getElementById('showSankeyBtn');
        if (showSankeyBtn) showSankeyBtn.style.display = 'none';
        
        // Ensure the button is hidden as per the requirement
        const showPacketSimilarityBtn = document.getElementById('showPacketSimilarityBtn');
        if (showPacketSimilarityBtn) showPacketSimilarityBtn.style.display = 'none';

        document.getElementById('toggleTimelineBtn').style.display = 'none';
        document.getElementById('createSubtreeBtn').style.display = 'none';
        document.getElementById('backToMainTreeBtn').style.display = 'none';
        
        const applyManualTimeBtn = document.getElementById('applyManualTimeBtn');
        if(applyManualTimeBtn) applyManualTimeBtn.disabled = true;

        clearSidebarVisualization();
        window.lastTreeData = null;
        window.fullTimelineData = null;

        const selectTimeframeManually = document.getElementById('selectTimeframeToggle').checked;

        if (selectTimeframeManually) {
            document.getElementById('topControls').style.display = 'block';
            const timelineCard = document.getElementById('timeline-card');
            if(timelineCard) timelineCard.style.display = 'block';
            await drawTimeline();
        } else {
            if (responseData.start_time && responseData.end_time) {
                document.getElementById('topControls').style.display = 'block';
                await initializeAndLoadVisuals(responseData.start_time, responseData.end_time);
            } else {
                throw new Error("Backend did not return a valid time range for automatic processing.");
            }
        }
    }

    function formatDateTimeForInput(date) {
        if (!date || isNaN(date.getTime())) return "";

        const pad = (num) => num.toString().padStart(2, '0');

        const year = date.getFullYear();
        const month = pad(date.getMonth() + 1);
        const day = pad(date.getDate());
        const hours = pad(date.getHours());
        const minutes = pad(date.getMinutes());
        const seconds = pad(date.getSeconds());

        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }

    function updateManualTimeInputs(startTime, endTime) {
        const manualStartTimeInput = document.getElementById('manualStartTime');
        const manualEndTimeInput = document.getElementById('manualEndTime');

        if (manualStartTimeInput && manualEndTimeInput) {
            manualStartTimeInput.value = formatDateTimeForInput(startTime);
            manualEndTimeInput.value = formatDateTimeForInput(endTime);
        }
    }

    function updateManualTimeButtonState() {
        const applyBtn = document.getElementById('applyManualTimeBtn');
        const startInput = document.getElementById('manualStartTime');
        const endInput = document.getElementById('manualEndTime');
    
        if (!applyBtn || !startInput || !endInput || !window.timelineXScale) return;
    
        let enable = false;
    
        const currentSelection = window.currentTimeSelection;
    
        if (currentSelection && startInput.value && endInput.value) {
            const inputStartTime = new Date(startInput.value);
            const inputEndTime = new Date(endInput.value);
    
            if (!isNaN(inputStartTime) && !isNaN(inputEndTime) && inputEndTime > inputStartTime) {
                const [domainStart, domainEnd] = window.timelineXScale.domain();
                if (inputStartTime >= domainStart && inputEndTime <= domainEnd) { 
                    const currentStartSeconds = Math.floor(currentSelection.startTime.getTime() / 1000);
                    const currentEndSeconds = Math.floor(currentSelection.endTime.getTime() / 1000);
                    const inputStartSeconds = Math.floor(inputStartTime.getTime() / 1000);
                    const inputEndSeconds = Math.floor(inputEndTime.getTime() / 1000);
    
                    if (inputStartSeconds !== currentStartSeconds || inputEndSeconds !== currentEndSeconds) {
                        enable = true;
                    }
                }
            }
        }
    
        applyBtn.disabled = !enable;
    }

    function disableManualApplyButton() {
        const applyBtn = document.getElementById('applyManualTimeBtn');
        if (applyBtn) {
            applyBtn.disabled = true;
        }
    }

    function handleCreateSubtree() {
        const selectedClusters = Array.from(clusterHighlightColors.keys());
        if (selectedClusters.length === 0) {
            alert("Please select one or more clusters from the heatmap to create a subtree.");
            return;
        }

        console.log(`Creating subtree from ${selectedClusters.length} selected clusters.`);
        showLoading();

        // Use the /create_subtree endpoint
        fetch(`${API_BASE_URL}/create_subtree`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ original_cluster_ids: selectedClusters })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(subtreeData => {
            hideLoading();
            if (subtreeData.error) {
                throw new Error(subtreeData.error);
            }

            // Save the current main tree view before showing the subtree
            mainTreeViewBeforeSubtree = window.lastTreeData;
            isSubtreeViewActive = true;

            // Display the new subtree
            showInlineDendrogram(subtreeData, document.getElementById("inline-dendrogram-container").clientHeight);
            
            // Update UI to reflect subtree view
            document.getElementById('treeControls').style.display = 'none';
            document.getElementById('backToMainTreeBtn').style.display = 'inline-block';
            updateSubtreeButtonState(); 

        })
        .catch(error => {
            hideLoading();
            console.error('Error creating subtree:', error);
            alert(`Failed to create subtree: ${error.message}`);
        });
    }

    function updateSubtreeButtonState() {
        const createBtn = document.getElementById('createSubtreeBtn');
        const backBtn = document.getElementById('backToMainTreeBtn');
        
        if (!createBtn || !backBtn) return;

        if (isSubtreeViewActive) {
            createBtn.style.display = 'none';
            backBtn.style.display = 'inline-block';
        } else {
            backBtn.style.display = 'none';
            // Show the create button only if there are clusters selected
            createBtn.style.display = clusterHighlightColors.size > 0 ? 'inline-block' : 'none';
        }
    }

    function createMagnifyingGlass() {
        magnifyingGlass = document.createElement('div');
        magnifyingGlass.classList.add('magnifying-glass');
        
        magnifyingContent = document.createElement('div');
        magnifyingContent.classList.add('magnifying-glass-content'); 

        magnifyingGlass.appendChild(magnifyingContent);
        document.body.appendChild(magnifyingGlass);
    }

    function moveMagnifyingGlass(e) {
        if (!isMagnifyingGlassActive || !magnifyingGlass) return;

        // Prevent the magnifying glass from hiding when the mouse is over its button
        const magnifyingGlassBtn = document.getElementById('magnifyingGlassBtn');
        if (e.target === magnifyingGlassBtn) {
            magnifyingGlass.style.display = 'none';
            return;
        } else {
            magnifyingGlass.style.display = 'block';
        }

        const zoomFactor = parseFloat(document.getElementById('magnifyingGlassZoom').value) || 2;
        const glassSize = 200; // The 'lens' size
        const halfGlassSize = glassSize / 2;
        const mouseX = e.pageX;
        const mouseY = e.pageY;

        // Position the magnifying glass 'lens'
        magnifyingGlass.style.left = (mouseX - halfGlassSize) + 'px';
        magnifyingGlass.style.top = (mouseY - halfGlassSize) + 'px';

        // Position the content inside the 'lens'
        if (magnifyingContent) {
            const contentX = -mouseX * zoomFactor + halfGlassSize;
            const contentY = -mouseY * zoomFactor + halfGlassSize;
            magnifyingContent.style.left = contentX + 'px';
            magnifyingContent.style.top = contentY + 'px';
        }
    }

    function toggleMagnifyingGlass(event) {
        isMagnifyingGlassActive = !isMagnifyingGlassActive;

        if (isMagnifyingGlassActive) {
            document.body.classList.add('magnifier-active'); // Add this line

            const zoomFactor = parseFloat(document.getElementById('magnifyingGlassZoom').value) || 2;
            magnifyingContent.style.transform = `scale(${zoomFactor})`;

            // Create a static clone of the body for magnification
            bodyClone = document.body.cloneNode(true);
            // Hide the cloned magnifying glass and its button to prevent recursion
            const clonedGlass = bodyClone.querySelector('.magnifying-glass');
            if (clonedGlass) clonedGlass.style.display = 'none';
            const clonedBtn = bodyClone.querySelector('#magnifyingGlassBtn');
            if (clonedBtn) clonedBtn.style.pointerEvents = 'none'; // Make button unclickable in clone

            // Set the dimensions of the clone to match the current body size
            bodyClone.style.width = document.body.offsetWidth + 'px';
            bodyClone.style.height = document.body.offsetHeight + 'px';
            
            // Add the clone to the magnifying glass content
            magnifyingContent.innerHTML = '';
            magnifyingContent.appendChild(bodyClone);

            // Add event listeners
            document.body.addEventListener('mousemove', moveMagnifyingGlass, { passive: true });
            document.addEventListener('keydown', handleEscKey);
            
            // Initial positioning
            if (event) {
                moveMagnifyingGlass(event);
            }

        } else {
            document.body.classList.remove('magnifier-active'); // Add this line

            // Deactivate and clean up
            magnifyingGlass.style.display = 'none';
            magnifyingContent.style.transform = 'scale(1)';
            document.body.removeEventListener('mousemove', moveMagnifyingGlass);
            document.removeEventListener('keydown', handleEscKey);
            if (magnifyingContent) magnifyingContent.innerHTML = '';
            bodyClone = null;
        }
    }

    function handleEscKey(e) {
        // Deactivate the magnifying glass if the Escape key is pressed
        if (e.key === 'Escape' && isMagnifyingGlassActive) {
            toggleMagnifyingGlass();
        }
    }

    document.getElementById('entropyMinFilter').style.display = 'none';
    document.getElementById('entropyMaxFilter').style.display = 'none';
    document.querySelector('label[for="entropyMinFilter"]').style.display = 'none';
    document.querySelector('label[for="entropyMaxFilter"]').style.display = 'none';