package com.ideascale.commons.authz.action

data class ActionMetadata(
    val id: String,
    val isWrite: Boolean,
    val isRead: Boolean
)

@CedarActionDslMarker
class ActionMetadataBuilder {
    private var isWrite: Boolean = false
    private var isRead: Boolean = false

    fun write() {
        isWrite = true
    }

    fun read() {
        isRead = true
    }

    fun build(id: String): ActionMetadata = ActionMetadata(
        id = id,
        isWrite = isWrite,
        isRead = isRead
    )
}

object ActionMetadataRegistry {
    private val metadataById = mutableMapOf<String, ActionMetadata>()

    fun register(action: Action, metadata: ActionMetadata) {
        metadataById[action.id] = metadata
    }

    fun register(
        action: Action,
        init: ActionMetadataBuilder.() -> Unit = {}
    ) {
        val metadata = ActionMetadataBuilder().apply(init).build(action.id)
        register(action, metadata)
    }

    fun get(actionId: String): ActionMetadata? = metadataById[actionId]

    fun isWrite(actionId: String): Boolean = metadataById[actionId]?.isWrite == true

    fun clear() {
        metadataById.clear()
    }
}

@DslMarker
annotation class CedarActionDslMarker
