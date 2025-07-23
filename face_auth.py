import face_recognition
import cv2

def capture_face_from_webcam(save_path="live_face.jpg"):
    cap = cv2.VideoCapture(0)
    print("📷 Press SPACE to capture face image. Press ESC to cancel.")

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        cv2.imshow("Capture Live Face (Press SPACE)", frame)

        key = cv2.waitKey(1)
        if key == 27:  # ESC
            cap.release()
            cv2.destroyAllWindows()
            return None
        elif key == 32:  # SPACE
            cv2.imwrite(save_path, frame)
            break

    cap.release()
    cv2.destroyAllWindows()
    return save_path

def verify_face(known_path, live_path):
    try:
        known_image = face_recognition.load_image_file(known_path)
        live_image = face_recognition.load_image_file(live_path)

        known_enc = face_recognition.face_encodings(known_image)
        live_enc = face_recognition.face_encodings(live_image)

        if not known_enc or not live_enc:
            print("⚠️ Face not detected in one of the images.")
            return False

        return face_recognition.compare_faces([known_enc[0]], live_enc[0])[0]
    except Exception as e:
        print(f"Face verification error: {e}")
        return False
