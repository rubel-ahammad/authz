package com.ideascale.commons.authz

/**
 * Where the request originated (useful for IP restrictions, stricter admin routes, etc.).
 */
enum class Channel {
    PUBLIC_API,
    ADMIN_UI,
    INTERNAL_JOB,
    INTERNAL_SERVICE
}
