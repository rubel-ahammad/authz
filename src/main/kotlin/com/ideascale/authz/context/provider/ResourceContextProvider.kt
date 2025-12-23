package com.ideascale.authz.context.provider

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.context.ResourceContext

interface ResourceContextProvider {
    fun load(resource: ResourceRef): ResourceContext
}
