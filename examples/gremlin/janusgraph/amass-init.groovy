// Connect to the Gremlin server
:remote connect tinkerpop.server conf/remote.yaml session
:remote console
// Wipe out all existing data
g.V().drop().iterate()
// Enter our test node for creating the indexes
g.addV('test').property('name', 'testing').property('type', 'test').iterate()
assets.tx().commit()
// Obtain the management interface and get the property keys of interest
mgmt = assets.openManagement()
name = mgmt.getPropertyKey('name')
ntype = mgmt.getPropertyKey('type')
// Build the indexes using the property keys
mgmt.buildIndex('byNameUnique', Vertex.class).addKey(name).unique().buildCompositeIndex()
mgmt.buildIndex('byTypeComposite', Vertex.class).addKey(ntype).buildCompositeIndex()
mgmt.buildIndex('byNameAndTypeComposite', Vertex.class).addKey(name).addKey(ntype).buildCompositeIndex()
mgmt.commit()
assets.tx().rollback()
// Wait for the indexes to be created
report = ManagementSystem.awaitGraphIndexStatus(assets, 'byNameUnique').call()
report = ManagementSystem.awaitGraphIndexStatus(assets, 'byTypeComposite').call()
report = ManagementSystem.awaitGraphIndexStatus(assets, 'byNameAndTypeComposite').call()
// Apply the indexes to all existing data
mgmt = assets.openManagement()
mgmt.updateIndex(mgmt.getGraphIndex("byNameUnique"), SchemaAction.REINDEX).get()
mgmt.updateIndex(mgmt.getGraphIndex("byTypeComposite"), SchemaAction.REINDEX).get()
mgmt.updateIndex(mgmt.getGraphIndex("byNameAndTypeComposite"), SchemaAction.REINDEX).get()
mgmt.commit()
// Block until the SchemaStatus is ENABLED
mgmt = assets.openManagement()
report = ManagementSystem.awaitGraphIndexStatus(assets, "byNameUnique").status(SchemaStatus.ENABLED).call()
report = ManagementSystem.awaitGraphIndexStatus(assets, "byTypeComposite").status(SchemaStatus.ENABLED).call()
report = ManagementSystem.awaitGraphIndexStatus(assets, "byNameAndTypeComposite").status(SchemaStatus.ENABLED).call()
mgmt.rollback()
// Remove the test node
g.V().has('type', 'test').drop().iterate()
assets.tx().commit()