package id.fatarc.trustgate

import android.app.Application

class TrustGateApplication : Application() {
    lateinit var container: TrustGateAppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = TrustGateAppContainer(this)
    }
}

