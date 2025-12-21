package com.ideascale.authz

/**
 * Stable set of resource types used across microservices.
 *
 * Why enum?
 * - Stable + discoverable
 * - Plays well with Kotlin/JVM + JSON serialization
 * - Prevents string drift ("Idea" vs "idea" vs "ideas")
 *
 * Evolve by ADDING new values; avoid renaming/removing to keep backward compatibility.
 */
enum class ResourceType {
    WORKSPACE,
    COMMUNITY,
    CAMPAIGN,
    GROUP,
    IDEA,
    MEMBER,

    // Optional: if you have a dedicated "subscription" entity
    SUBSCRIPTION,

    // Optional: common cross-cutting resources
    TRANSLATION,
    MODERATION_CASE
}
