package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.ResourceContext

interface ResourceContextProvider {
    fun load(resource: ResourceRef): ResourceContext
}
