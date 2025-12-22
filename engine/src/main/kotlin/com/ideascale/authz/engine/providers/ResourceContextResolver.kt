package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.ResourceContext

interface ResourceContextResolver {
    fun resolve(resource: ResourceRef): ResourceContext
}
