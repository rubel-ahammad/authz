package com.ideascale.commons.authz.context

import com.ideascale.commons.authz.resource.Resource

/**
 * Sealed hierarchy of resource contexts.
 * Each resource type has its own context with type-specific attributes and relationships.
 *
 * All contexts include:
 * - Resource identity (type, id)
 * - Workspace attributes (always required - tenant-level constraints)
 * - Type-specific attributes and relationships
 */
sealed interface ResourceContext {
    val type: Resource
    val id: Long
    val workspace: WorkspaceAttributes
}

// ============ WORKSPACE ============

data class WorkspaceContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes
) : ResourceContext {
    override val type: Resource = Resource.WORKSPACE
}

// ============ COMMUNITY ============

data class CommunityContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes,
    // Community-specific attributes
    val status: CommunityStatus = CommunityStatus.ACTIVE,
    val isPrivate: Boolean = false
) : ResourceContext {
    override val type: Resource = Resource.COMMUNITY
}

// ============ CAMPAIGN ============

data class CampaignContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes,
    val community: CommunityAttributes,
    // Campaign-specific attributes
    val state: CampaignState = CampaignState.LAUNCHED
) : ResourceContext {
    override val type: Resource = Resource.CAMPAIGN
}

// ============ IDEA ============

data class IdeaContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes,
    val community: CommunityAttributes,
    val campaign: CampaignAttributes,
    // Idea-specific attributes
    val state: IdeaState = IdeaState.ACTIVE,
    // Idea-specific relationships (ReBAC)
    val owner: Long,
    val contributors: Set<Long> = emptySet(),
    val viewers: Set<Long> = emptySet()
) : ResourceContext {
    override val type: Resource = Resource.IDEA

    fun isOwner(principalId: Long): Boolean = owner == principalId
    fun isContributor(principalId: Long): Boolean = contributors.contains(principalId)
    fun isViewer(principalId: Long): Boolean = viewers.contains(principalId)
    fun hasAnyRelationship(principalId: Long): Boolean =
        isOwner(principalId) || isContributor(principalId) || isViewer(principalId)
}

// ============ GROUP ============

data class GroupContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes,
    // Group-specific relationships
    val members: Set<Long> = emptySet()
) : ResourceContext {
    override val type: Resource = Resource.GROUP

    fun isMember(principalId: Long): Boolean = members.contains(principalId)
}

// ============ MEMBER ============

data class MemberContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes,
    // Member-specific attributes
    val status: MemberStatus = MemberStatus.ACTIVE
) : ResourceContext {
    override val type: Resource = Resource.MEMBER
}

// ============ CUSTOM FIELD ============

data class CustomFieldContext(
    override val id: Long,
    override val workspace: WorkspaceAttributes,
    // Optional - custom fields can be workspace-level or community-level
    val community: CommunityAttributes? = null
) : ResourceContext {
    override val type: Resource = Resource.CUSTOM_FIELD
}
