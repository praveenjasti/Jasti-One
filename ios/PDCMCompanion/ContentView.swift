import SwiftUI
import Photos
import Contacts

@MainActor
final class InventoryModel: ObservableObject {
    @Published var photoStatus = "Not scanned"
    @Published var contactStatus = "Not scanned"

    func inspectPhotos() async {
        var status = PHPhotoLibrary.authorizationStatus(for: .readWrite)
        if status == .notDetermined {
            status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
        }
        guard status == .authorized || status == .limited else {
            photoStatus = "Photo access not granted"
            return
        }
        let assets = PHAsset.fetchAssets(with: nil)
        photoStatus = "\(assets.count) accessible photo/video assets. Read-only inventory."
    }

    func inspectContacts() async {
        let store = CNContactStore()
        do {
            let status = CNContactStore.authorizationStatus(for: .contacts)
            if status == .notDetermined {
                _ = try await store.requestAccess(for: .contacts)
            }
            let request = CNContactFetchRequest(keysToFetch: [CNContactIdentifierKey as CNKeyDescriptor])
            var count = 0
            try store.enumerateContacts(with: request) { _, _ in count += 1 }
            contactStatus = "\(count) accessible contacts. Read-only inventory."
        } catch {
            contactStatus = "Contacts unavailable: \(error.localizedDescription)"
        }
    }
}

struct ContentView: View {
    @StateObject private var model = InventoryModel()
    var body: some View {
        NavigationStack {
            List {
                Section("Photos and videos") {
                    Text(model.photoStatus)
                    Button("Request access and inspect") { Task { await model.inspectPhotos() } }
                }
                Section("Contacts") {
                    Text(model.contactStatus)
                    Button("Request access and count") { Task { await model.inspectContacts() } }
                }
                Section("Safety") {
                    Text("Read-only starter. Nothing is deleted or uploaded.")
                }
            }
            .navigationTitle("Jasti One")
        }
    }
}
