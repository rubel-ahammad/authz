package com.ideascale.authz.context.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.context.ResourceContext

interface ResourceContextProvider {
    fun load(resource: ResourceRef): ResourceContext
}
