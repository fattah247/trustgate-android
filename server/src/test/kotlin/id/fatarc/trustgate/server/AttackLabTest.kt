package id.fatarc.trustgate.server

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.attacklab.AttackLab
import id.fatarc.trustgate.attacklab.Reply
import id.fatarc.trustgate.attacklab.Transport
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.ServerHealth
import id.fatarc.trustgate.testing.developmentPolicy
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import org.junit.Test

/** Runs every attack in the lab against the server's routes, so a change that lets one through fails the build. */
class AttackLabTest {
    private class TestTransport(private val client: HttpClient) : Transport {
        override fun post(path: String, body: String, headers: Map<String, String>): Reply = runBlocking {
            val response = client.post(path) {
                contentType(ContentType.Application.Json)
                headers.forEach { (name, value) -> header(name, value) }
                setBody(body)
            }
            Reply(response.status.value, response.bodyAsText())
        }

        override fun get(path: String): Reply = runBlocking {
            val response = client.get(path)
            Reply(response.status.value, response.bodyAsText())
        }
    }

    @Test
    fun `every attack in the lab is stopped`() = testApplication {
        application { trustGateModule(ReferenceBackend(developmentPolicy), ServerHealth(status = "ok", policy = "development"), adminToken = "t".repeat(40)) }

        val results = AttackLab(TestTransport(client)).run()

        assertThat(results.filterNot { it.stopped }.map { "${it.attack}: ${it.serverSaid}" }).isEmpty()
        assertThat(results.size).isAtLeast(14)
    }
}
