package com.ideascale.authz.core

/**
 * Declarative resource hierarchy schema.
 *
 * Documents the parent-child relationships between resource types:
 *
 *   WORKSPACE (root)
 *   ├── COMMUNITY
 *   │   └── CAMPAIGN
 *   │       └── IDEA
 *   ├── MEMBER
 *   ├── GROUP
 *   └── SUBSCRIPTION
 *
 *   Cross-cutting (no parent):
 *   ├── TRANSLATION
 *   └── MODERATION_CASE
 */
object EntitySchema {

    private val parentTypes: Map<ResourceType, ResourceType?> = mapOf(
        // Root
        ResourceType.WORKSPACE to null,

        // Workspace children
        ResourceType.COMMUNITY to ResourceType.WORKSPACE,
        ResourceType.MEMBER to ResourceType.WORKSPACE,
        ResourceType.GROUP to ResourceType.WORKSPACE,
        ResourceType.SUBSCRIPTION to ResourceType.WORKSPACE,

        // Community children
        ResourceType.CAMPAIGN to ResourceType.COMMUNITY,

        // Campaign children
        ResourceType.IDEA to ResourceType.CAMPAIGN,

        // Cross-cutting (no hierarchy)
        ResourceType.TRANSLATION to null,
        ResourceType.MODERATION_CASE to null,
    )

    /**
     * Returns the immediate parent type, or null if root/cross-cutting.
     */
    fun parentOf(type: ResourceType): ResourceType? = parentTypes[type]

    /**
     * Returns all ancestors from immediate parent up to root.
     * Example: ancestorsOf(IDEA) = [CAMPAIGN, COMMUNITY, WORKSPACE]
     */
    fun ancestorsOf(type: ResourceType): List<ResourceType> = buildList {
        var current = parentOf(type)
        while (current != null) {
            add(current)
            current = parentOf(current)
        }
    }

    /**
     * Returns true if [child] is a descendant of [ancestor].
     * Example: isDescendantOf(IDEA, WORKSPACE) = true
     */
    fun isDescendantOf(child: ResourceType, ancestor: ResourceType): Boolean =
        ancestorsOf(child).contains(ancestor)

    /**
     * Returns the root type for a given type (follows parents to root).
     * Returns the type itself if it has no parent.
     */
    fun rootOf(type: ResourceType): ResourceType =
        ancestorsOf(type).lastOrNull() ?: type

    /**
     * Returns all types that have [type] as their parent.
     */
    fun childrenOf(type: ResourceType): List<ResourceType> =
        parentTypes.filterValues { it == type }.keys.toList()

    /**
     * Returns depth in hierarchy (WORKSPACE=0, COMMUNITY=1, CAMPAIGN=2, IDEA=3).
     */
    fun depthOf(type: ResourceType): Int = ancestorsOf(type).size
}
