package com.example.wallet

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.compose.animation.*
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.example.wallet.ui.theme.WalletTheme
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import androidx.camera.mlkit.vision.MlKitAnalyzer
import androidx.camera.view.CameraController.COORDINATE_SYSTEM_VIEW_REFERENCED
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import org.json.JSONObject
import org.json.JSONArray
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import uniffi.agever.AgeVerCredential
import uniffi.agever.AgeVerGapCredential
import uniffi.agever.AgeVerHolderPublicKey
import java.math.BigInteger
import java.security.interfaces.ECPublicKey

sealed class AppScreen(val order: Int) {
    object Home : AppScreen(0)
    object Scanner : AppScreen(1)
    data class Presentation(val sessionId: String, val isDeepLink: Boolean = false) : AppScreen(2)
}

class MainActivity : ComponentActivity() {
    private var deepLinkSessionId = mutableStateOf<String?>(null)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        if (intent.action == Intent.ACTION_VIEW) {
            val data = intent.data
            if (data?.scheme == "demowallet" && data.host == "verify") {
                val sessid = data.getQueryParameter("sessid")
                if (sessid != null) {
                    deepLinkSessionId.value = sessid
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class, ExperimentalPermissionsApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        handleIntent(intent)
        enableEdgeToEdge()
        setContent {
            var currentScreen by remember { mutableStateOf<AppScreen>(AppScreen.Home) }

            val dlSessionId by deepLinkSessionId
            LaunchedEffect(dlSessionId) {
                dlSessionId?.let {
                    currentScreen = AppScreen.Presentation(it, isDeepLink = true)
                    deepLinkSessionId.value = null
                }
            }

            var credentials by remember { mutableStateOf<List<AgeVerCredential>>(emptyList()) }
            var selectedHandle by remember { mutableStateOf<ULong?>(null) }
            var holderPublicKey by remember { mutableStateOf<AgeVerHolderPublicKey?>(null) }
            var isHardwareBacked by remember { mutableStateOf(false) }
            var isFetching by remember { mutableStateOf(false) }
            var errorMessage by remember { mutableStateOf<String?>(null) }

            var gapList by remember { mutableStateOf<List<AgeVerGapCredential>?>(null) }
            var isUpdatingRevocation by remember { mutableStateOf(false) }
            var revocationUpdateTime by remember { mutableStateOf<Long?>(null) }
            var revocationUpdateError by remember { mutableStateOf<String?>(null) }
            // Only entries for credentials that have actually been checked against a fetched
            // gap list are present here - absence (not false) means "not checked yet".
            var validityByHandle by remember { mutableStateOf<Map<ULong, Boolean>>(emptyMap()) }
            val scope = rememberCoroutineScope()

            val context = androidx.compose.ui.platform.LocalContext.current
            val keyManager = remember { HardwareKeyManager(context) }

            val cameraPermissionState = rememberPermissionState(android.Manifest.permission.CAMERA)
            val client = remember {
                OkHttpClient.Builder()
                    .connectTimeout(30, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .build()
            }

            val url1 = "http://127.0.0.1:3000/issue"
            val url2 = "http://127.0.0.1:3000/validate"
            val url3 = "http://127.0.0.1:3000/revocation-status"

            fun updateRevocationStatus() {
                isUpdatingRevocation = true
                revocationUpdateError = null
                scope.launch {
                    try {
                        val start = System.currentTimeMillis()
                        val gapResult = withContext(Dispatchers.IO) {
                            val request = Request.Builder().url(url3).get().build()
                            client.newCall(request).execute().use { response ->
                                if (response.isSuccessful) response.body?.string() else
                                    throw Exception(response.body?.string())
                            }
                        }
                        val gapsJson = JSONObject(gapResult.orEmpty()).getJSONArray("gaps")
                        val freshGapList = (0 until gapsJson.length()).map { i ->
                            uniffi.agever.gapCredentialFromJwt(gapsJson.getString(i))
                        }
                        gapList = freshGapList
                        validityByHandle = credentials.associate { cred ->
                            cred.revHandle() to (uniffi.agever.findBracket(freshGapList, cred.revHandle()) != null)
                        }
                        revocationUpdateTime = System.currentTimeMillis() - start
                    } catch (e: Exception) {
                        revocationUpdateError = e.message
                    } finally {
                        isUpdatingRevocation = false
                    }
                }
            }

            fun requestNewCredential() {
                isFetching = true
                errorMessage = null
                scope.launch {
                    try {
                        val result = withContext(Dispatchers.IO) {
                            val chain = keyManager.getCertificateChain()
                            val certsBase64 = chain.map {
                                android.util.Base64.encodeToString(it.encoded, android.util.Base64.NO_WRAP)
                            }
                            Log.d("MainActivity", "Requesting credential with chain: $certsBase64")

                            val jsonBody = JSONObject().apply {
                                put("cert_chain", JSONArray(certsBase64))
                            }
                            val requestBody = jsonBody.toString()
                                .toRequestBody("application/json; charset=utf-8".toMediaType())
                            val request = Request.Builder().url(url1).post(requestBody).build()
                            client.newCall(request).execute().use { response ->
                                if (response.isSuccessful) response.body?.string() else
                                    throw Exception(response.body?.string())
                            }
                        }
                        val newCredential = uniffi.agever.credentialFromJwt(result.orEmpty())
                        credentials = credentials + newCredential
                        selectedHandle = newCredential.revHandle()
                    } catch (e: Exception) {
                        errorMessage = e.message
                    } finally {
                        isFetching = false
                    }
                }
            }

            LaunchedEffect(Unit) {
                if (!cameraPermissionState.status.isGranted) {
                    cameraPermissionState.launchPermissionRequest()
                }

                try {
                    val cert = keyManager.getOrGenerateKey()
                    val ecPublicKey = cert.publicKey as ECPublicKey

                    // The raw uncompressed key is always the last 65 bytes of the X.509 encoding
                    val uncompressedPk = ecPublicKey.encoded.sliceArray(ecPublicKey.encoded.size - 65 until ecPublicKey.encoded.size)// Result: [0x04, X-bytes (32), Y-bytes (32)]
                    val hpk = uniffi.agever.holderPkFromUncompressedSec1(uncompressedPk)

                    isHardwareBacked = keyManager.isKeyHardwareBacked()
                    holderPublicKey = hpk
                } catch (e: Exception) {
                    errorMessage = "Key error: ${e.message}"
                }

                requestNewCredential()
            }

            WalletTheme {
                AnimatedContent(
                    targetState = currentScreen,
                    label = "ScreenTransition",
                    transitionSpec = {
                        if (targetState.order > initialState.order) {
                            // Forward: Slide from Right to Left
                            slideInHorizontally { it } + fadeIn() togetherWith
                                    slideOutHorizontally { -it } + fadeOut()
                        } else {
                            // Backward: Slide from Left to Right
                            slideInHorizontally { -it } + fadeIn() togetherWith
                                    slideOutHorizontally { it } + fadeOut()
                        }
                    }
                ) { screen ->
                    when (screen) {
                        is AppScreen.Home -> {
                            Scaffold(
                                modifier = Modifier.fillMaxSize(),
                                topBar = {
                                    CenterAlignedTopAppBar(
                                        title = { Text("AgeVer Demo") },
                                        colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                                            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                                        )
                                    )
                                }
                            ) { innerPadding ->
                                DemoScreen(
                                    modifier = Modifier
                                        .padding(innerPadding)
                                        .fillMaxSize(),
                                    credentials = credentials,
                                    selectedHandle = selectedHandle,
                                    onSelectHandle = { selectedHandle = it },
                                    holderPublicKey = holderPublicKey,
                                    isHardwareBacked = isHardwareBacked,
                                    isFetching = isFetching,
                                    errorMessage = errorMessage,
                                    gapList = gapList,
                                    isUpdatingRevocation = isUpdatingRevocation,
                                    revocationUpdateTime = revocationUpdateTime,
                                    revocationUpdateError = revocationUpdateError,
                                    validityByHandle = validityByHandle,
                                    onUpdateRevocation = { updateRevocationStatus() },
                                    onRequestNewCredential = { requestNewCredential() },
                                    onNavigateToScanner = {
                                        errorMessage = null
                                        currentScreen = AppScreen.Scanner
                                    }
                                )
                            }
                        }
                        is AppScreen.Scanner -> {
                            ScannerScreen(
                                onDismiss = { currentScreen = AppScreen.Home },
                                onScanned = { sessionId ->
                                    currentScreen = AppScreen.Presentation(sessionId)
                                }
                            )
                        }
                        is AppScreen.Presentation -> {
                            PresentationScreen(
                                sessionId = screen.sessionId,
                                credential = credentials.find { it.revHandle() == selectedHandle },
                                gapList = gapList,
                                holderPublicKey = holderPublicKey,
                                keyManager = keyManager,
                                client = client,
                                url = url2,
                                onFinish = { success, msg ->
                                    if (!success) {
                                        errorMessage = msg
                                    }
                                    if (screen.isDeepLink) {
                                        this@MainActivity.finish()
                                    } else {
                                        currentScreen = AppScreen.Home
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun DemoScreen(
    modifier: Modifier = Modifier,
    credentials: List<AgeVerCredential>,
    selectedHandle: ULong?,
    onSelectHandle: (ULong) -> Unit,
    holderPublicKey: AgeVerHolderPublicKey?,
    isHardwareBacked: Boolean,
    isFetching: Boolean,
    errorMessage: String?,
    gapList: List<AgeVerGapCredential>?,
    isUpdatingRevocation: Boolean,
    revocationUpdateTime: Long?,
    revocationUpdateError: String?,
    validityByHandle: Map<ULong, Boolean>,
    onUpdateRevocation: () -> Unit,
    onRequestNewCredential: () -> Unit,
    onNavigateToScanner: () -> Unit
) {
    val selectedCredential = credentials.find { it.revHandle() == selectedHandle }
    val selectedValid = selectedHandle?.let { validityByHandle[it] }

    Column(
        modifier = modifier.padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        ElevatedCard(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.elevatedCardElevation(defaultElevation = 6.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.Start
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.size(8.dp))
                    Text(
                        text = "Identity Status",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))

                StatusRow(
                    label = "Holder Key",
                    isOk = holderPublicKey != null,
                    loading = false,
                    subtitle = if (isHardwareBacked) "Hardware-backed" else "Software-backed"
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(
                    label = "Credentials",
                    isOk = credentials.isNotEmpty(),
                    loading = isFetching,
                    subtitle = if (credentials.isNotEmpty()) "${credentials.size} held" else null
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(
                    label = "Status",
                    isOk = selectedValid == true,
                    loading = isUpdatingRevocation,
                    subtitle = when {
                        selectedCredential == null -> null
                        revocationUpdateError != null -> revocationUpdateError
                        selectedValid == false -> "This credential is no longer valid"
                        selectedValid == true -> "Updated in ${revocationUpdateTime}ms"
                        gapList != null -> "Refresh to check this credential"
                        else -> "Not fetched yet"
                    },
                    icon = if (selectedValid == false) Icons.Default.Cancel
                        else if (selectedValid == true) Icons.Default.CheckCircle
                        else Icons.Default.Error
                )

                if (credentials.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Held Credentials",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(credentials, key = { it.revHandle().toString() }) { cred ->
                            CredentialChip(
                                credential = cred,
                                isSelected = cred.revHandle() == selectedHandle,
                                isValid = validityByHandle[cred.revHandle()],
                                onClick = { onSelectHandle(cred.revHandle()) }
                            )
                        }
                    }
                }

                if (selectedCredential != null) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Credential Details",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    val claimsJson = remember(selectedCredential) {
                        try { JSONObject(selectedCredential.claimsJsonStr()) } catch (e: Exception) { null }
                    }
                    claimsJson?.let { ClaimsList(it) }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = !isFetching,
            onClick = onRequestNewCredential
        ) {
            Text(if (credentials.isEmpty()) "Request Credential" else "Request New Credential")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = !isUpdatingRevocation,
            onClick = onUpdateRevocation
        ) {
            Text(if (gapList == null) "Update Status" else "Refresh Status")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            onClick = onNavigateToScanner,
            enabled = selectedCredential != null && selectedValid == true
        ) {
            Icon(Icons.Default.QrCodeScanner, contentDescription = null)
            Spacer(modifier = Modifier.size(8.dp))
            Text("Verify Credential")
        }

        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(24.dp))
            ElevatedCard(
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Error,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.size(12.dp))
                    Text(
                        text = errorMessage,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

@Composable
fun CredentialChip(
    credential: AgeVerCredential,
    isSelected: Boolean,
    isValid: Boolean?,
    onClick: () -> Unit
) {
    val claimsJson = remember(credential) {
        try { JSONObject(credential.claimsJsonStr()) } catch (e: Exception) { null }
    }
    val name = claimsJson?.optJSONObject("name")?.optString("val") ?: "Credential"
    val shortHandle = credential.revHandle().toString(16).takeLast(6)

    ElevatedCard(
        modifier = Modifier.clickable(onClick = onClick),
        colors = CardDefaults.elevatedCardColors(
            containerColor = if (isSelected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = name,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                )
                Text(
                    text = "#$shortHandle",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline
                )
            }
            if (isValid != null) {
                Spacer(modifier = Modifier.size(6.dp))
                Icon(
                    imageVector = if (isValid) Icons.Default.CheckCircle else Icons.Default.Cancel,
                    contentDescription = null,
                    tint = if (isValid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

@Composable
fun ScannerScreen(
    onDismiss: () -> Unit,
    onScanned: (String) -> Unit
) {
    Box(modifier = Modifier.fillMaxSize()) {
        ScannerView(
            onScanned = { scannedValue ->
                try {
                    val sessionId = JSONObject(scannedValue).getString("sessid")
                    onScanned(sessionId)
                } catch (e: Exception) {
                    // Handle case where QR is not a valid JSON with sessid
                }
            }
        )

        // Cancel Button
        TextButton(
            onClick = onDismiss,
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 48.dp, end = 16.dp),
            colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
        ) {
            Icon(Icons.Default.Close, contentDescription = "Cancel")
            Spacer(Modifier.size(8.dp))
            Text("Cancel")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PresentationScreen(
    sessionId: String,
    credential: AgeVerCredential?,
    gapList: List<AgeVerGapCredential>?,
    holderPublicKey: AgeVerHolderPublicKey?,
    keyManager: HardwareKeyManager,
    client: OkHttpClient,
    url: String,
    onFinish: (Boolean, String?) -> Unit
) {
    var isConfirmed by remember { mutableStateOf(false) }
    var isProcessing by remember { mutableStateOf(false) }
    var resultMessage by remember { mutableStateOf<String?>(null) }
    var success by remember { mutableStateOf(false) }
    var statusText by remember { mutableStateOf("Generating presentation") }
    var signingTime by remember { mutableStateOf<Long?>(null) }
    var presentationTime by remember { mutableStateOf<Long?>(null) }
    var verificationTime by remember { mutableStateOf<Long?>(null) }

    val scope = rememberCoroutineScope()

    fun startPresentation() {
        isConfirmed = true
        isProcessing = true
        scope.launch {
            try {
                val (pres, signMs, presentMs) = withContext(Dispatchers.IO) {
                    val today = (System.currentTimeMillis() / 1000).toULong()
                    val nonce = "demo-nonce-${sessionId}".toByteArray()

                    // Hardware-based signing
                    val startTimeSign = System.currentTimeMillis()
                    val sigBytes = keyManager.sign(nonce)
                    val signMs = System.currentTimeMillis() - startTimeSign
                    val sig = uniffi.agever.holderSigFromDerBytes(sigBytes)

                    val cred = credential!!
                    val revHandle = cred.revHandle()
                    // Scanning is disabled from the home screen until the revocation status has
                    // been fetched at least once, so gapList is always set here.
                    val bracket = uniffi.agever.findBracket(gapList!!, revHandle)
                        ?: throw Exception("This credential is no longer valid.")

                    val startTimePresent = System.currentTimeMillis()
                    val presentation = uniffi.agever.genPresentation(cred, holderPublicKey!!, today, nonce, sig, bracket)
                    val presentMs = System.currentTimeMillis() - startTimePresent

                    Triple(presentation, signMs, presentMs)
                }
                signingTime = signMs
                presentationTime = presentMs

                statusText = "Verifying presentation"

                val startTimeVer = System.currentTimeMillis()
                val result = withContext(Dispatchers.IO) {
                    // Presentation verification
                    val formBody = FormBody.Builder()
                        .add("session_id", sessionId)
                        .add("token", pres.toBase64())
                        .build()
                    val request = Request.Builder().url(url).post(formBody).build()
                    client.newCall(request).execute().use { response ->
                        if (response.isSuccessful) {
                            Result.success(true)
                        } else {
                            Result.failure(Exception(response.body?.string() ?: "Unknown error."))
                        }
                    }
                }
                verificationTime = System.currentTimeMillis() - startTimeVer
                if (result.isSuccess) {
                    success = true
                    resultMessage = "The credential was verified successfully."
                } else {
                    success = false
                    val serverMessage = result.exceptionOrNull()?.message
                    resultMessage = if (serverMessage == "invalid token") {
                        "Your revocation status is out of date. Go back and refresh status, then try again."
                    } else {
                        serverMessage
                    }
                }
            } catch (e: Exception) {
                success = false
                resultMessage = e.message
            } finally {
                isProcessing = false
            }
        }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Presentation") },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            if (!isConfirmed) {
                Text(
                    text = "Present Credential?",
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "The following information will be shared with the verifier:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(24.dp))

                val displayClaims = remember(credential) {
                    try {
                        val original = JSONObject(credential?.claimsJsonStr() ?: "{}")
                        val modified = JSONObject()
                        val now = SimpleDateFormat("MMM dd, yyyy hh:mm", Locale.getDefault()).format(Date())

                        modified.put("name", JSONObject().put("type", "string").put("val", "<hidden>"))
                        
                        // Show above16 as true (revealed)
                        if (original.has("above16")) {
                            modified.put("above16", original.getJSONObject("above16"))
                        }
                        
                        modified.put("above18", JSONObject().put("type", "string").put("val", "<hidden>"))
                        modified.put("nbf", JSONObject().put("type", "string").put("val", "earlier than $now"))
                        modified.put("exp", JSONObject().put("type", "string").put("val", "later than $now"))
                        modified
                    } catch (e: Exception) {
                        JSONObject()
                    }
                }

                ElevatedCard(
                    modifier = Modifier.fillMaxWidth(),
                    elevation = CardDefaults.elevatedCardElevation(defaultElevation = 4.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        ClaimsList(displayClaims)
                    }
                }

                Spacer(modifier = Modifier.height(32.dp))

                Button(
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    enabled = gapList != null,
                    onClick = { startPresentation() }
                ) {
                    Text("Confirm & Share")
                }
                Spacer(modifier = Modifier.height(12.dp))
                TextButton(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { onFinish(false, null) }
                ) {
                    Text("Cancel")
                }
            } else if (isProcessing) {
                CircularProgressIndicator(modifier = Modifier.size(64.dp))
                Spacer(modifier = Modifier.height(24.dp))
                Text(statusText, style = MaterialTheme.typography.titleMedium)
            } else {
                Icon(
                    imageVector = if (success) Icons.Default.CheckCircle else Icons.Default.Error,
                    contentDescription = null,
                    modifier = Modifier.size(80.dp),
                    tint = if (success) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    text = if (success) "Success!" else "Verification Failed",
                    style = MaterialTheme.typography.headlineMedium,
                    color = if (success) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = resultMessage ?: "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                if (signingTime != null && presentationTime != null && verificationTime != null) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "Signing: ${signingTime}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                        Text(
                            text = "Presentation generation: ${presentationTime}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                        Text(
                            text = "Verification (network + server): ${verificationTime}ms",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }

                Spacer(modifier = Modifier.height(48.dp))
                Button(
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    onClick = { onFinish(success, if (success) null else resultMessage) }
                ) {
                    Text("OK")
                }
            }
        }
    }
}

@Composable
fun ClaimsList(claimsJson: JSONObject) {
    val displayKeys = listOf(
        "name" to "Name",
        "above16" to "Above 16",
        "above18" to "Above 18",
        "nbf" to "Valid From",
        "exp" to "Expires At"
    )
    displayKeys.forEach { (key, label) ->
        claimsJson.optJSONObject(key)?.let { valueObj ->
            ClaimRow(label = label, valueObj = valueObj)
        }
    }
}

@Composable
fun StatusRow(
    label: String,
    isOk: Boolean,
    loading: Boolean,
    subtitle: String? = null,
    icon: ImageVector = if (isOk) Icons.Default.CheckCircle else Icons.Default.Error
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column {
            Text(text = label, style = MaterialTheme.typography.bodyLarge)
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                )
            }
        }
        if (loading) {
            CircularProgressIndicator(
                modifier = Modifier.size(24.dp),
                strokeWidth = 2.dp
            )
        } else {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (isOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
            )
        }
    }
}

@Composable
fun ClaimRow(label: String, valueObj: JSONObject) {
    val type = valueObj.optString("type")

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        when (type) {
            "string" -> {
                Text(
                    text = valueObj.optString("val"),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            "bool" -> {
                val isTrue = valueObj.optBoolean("val")
                Icon(
                    imageVector = if (isTrue) Icons.Default.CheckCircle else Icons.Default.Close,
                    contentDescription = null,
                    tint = if (isTrue) Color(0xFF4CAF50) else MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(20.dp)
                )
            }
            "raw" -> {
                val timestamp = valueObj.optLong("val")
                val dateStr = try {
                    val date = Date(timestamp * 1000)
                    SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault()).format(date)
                } catch (e: Exception) {
                    timestamp.toString()
                }
                Text(
                    text = dateStr,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            else -> {
                Text(
                    text = valueObj.opt("val")?.toString() ?: "",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
fun ScannerView(onScanned: (String) -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current

    val cameraController = remember {
        LifecycleCameraController(context).apply {
            val options = BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build()
            val barcodeScanner = BarcodeScanning.getClient(options)

            setImageAnalysisAnalyzer(
                ContextCompat.getMainExecutor(context),
                MlKitAnalyzer(
                    listOf(barcodeScanner),
                    COORDINATE_SYSTEM_VIEW_REFERENCED,
                    ContextCompat.getMainExecutor(context)
                ) { result ->
                    val barcodes = result.getValue(barcodeScanner)
                    if (!barcodes.isNullOrEmpty()) {
                        barcodes.firstOrNull()?.rawValue?.let {
                            onScanned(it)
                        }
                    }
                }
            )
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        AndroidView(
            factory = { context ->
                PreviewView(context).apply {
                    this.controller = cameraController
                    cameraController.bindToLifecycle(lifecycleOwner)
                }
            },
            modifier = Modifier.fillMaxSize()
        )

        // Scanner Overlay (Visual frame)
        Icon(
            imageVector = Icons.Default.QrCodeScanner,
            contentDescription = null,
            modifier = Modifier.size(200.dp),
            tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
        )
    }
}

@Preview(showBackground = true)
@Composable
fun DemoScreenPreview() {
    WalletTheme {
        DemoScreen(
            credentials = emptyList(),
            selectedHandle = null,
            onSelectHandle = {},
            holderPublicKey = null,
            isHardwareBacked = false,
            isFetching = false,
            errorMessage = null,
            gapList = null,
            isUpdatingRevocation = false,
            revocationUpdateTime = null,
            revocationUpdateError = null,
            validityByHandle = emptyMap(),
            onUpdateRevocation = {},
            onRequestNewCredential = {},
            onNavigateToScanner = {}
        )
    }
}
