package com.ideascale.commons.authz.fixture

import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.context.provider.AttributeContextProvider
import com.ideascale.commons.authz.core.AuthzContext
import com.ideascale.commons.authz.core.Channel
import com.ideascale.commons.authz.core.ResourceRef

class TestAttributeContextProvider(
    private val attributeContext: AttributeContext
) : AttributeContextProvider {

    override fun load(
        workspaceId: String,
        memberId: String?,
        resource: ResourceRef,
        resourceContext: ResourceContext,
        ctx: AuthzContext
    ): AttributeContext = attributeContext

    companion object {
        fun activeWorkspace(): TestAttributeContextProvider {
            return TestAttributeContextProvider(
                AttributeContext(
                    workspace = WorkspaceAttrs(
                        subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                        network = NetworkAttrs(IpRestrictionResult.Allowed),
                        emailDomain = EmailDomainAttrs(),
                        flags = WorkspaceFlags(isPublic = true)
                    ),
                    member = MemberAttrs(MemberStatus.MEMBER),
                    request = RequestAttrs(ip = null, channel = Channel.PUBLIC_API)
                )
            )
        }

        fun activeWorkspaceForAnonymous(): TestAttributeContextProvider {
            return TestAttributeContextProvider(
                AttributeContext(
                    workspace = WorkspaceAttrs(
                        subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                        network = NetworkAttrs(IpRestrictionResult.Allowed),
                        emailDomain = EmailDomainAttrs(),
                        flags = WorkspaceFlags(isPublic = true)
                    ),
                    member = MemberAttrs(MemberStatus.MEMBER),
                    request = RequestAttrs(ip = null, channel = Channel.PUBLIC_API)
                )
            )
        }

        fun privateWorkspace(): TestAttributeContextProvider {
            return TestAttributeContextProvider(
                AttributeContext(
                    workspace = WorkspaceAttrs(
                        subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                        network = NetworkAttrs(IpRestrictionResult.Allowed),
                        emailDomain = EmailDomainAttrs(),
                        flags = WorkspaceFlags(isPublic = false)
                    ),
                    member = MemberAttrs(MemberStatus.MEMBER),
                    request = RequestAttrs(ip = null, channel = Channel.PUBLIC_API)
                )
            )
        }
    }
}
