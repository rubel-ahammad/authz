package com.ideascale.commons.authz.context.provider

import com.ideascale.commons.authz.resource.ResourceRef
import com.ideascale.commons.authz.context.ResourceContext

interface ResourceContextProvider {
    fun load(resource: ResourceRef): ResourceContext
}
