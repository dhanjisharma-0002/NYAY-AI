"""
NYAYAI - Forensic Image Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides non-destructive image inspection including:
- Image format
- Dimensions
- Color mode
- EXIF metadata
- Basic image properties

The original evidence file is opened read-only and is never modified.
"""

from typing import Dict, Any
from PIL import Image, ExifTags


class ForensicImageAnalyzer:
    """
    Non-destructive forensic image inspection engine.
    """

    def extract_exif(self, image: Image.Image) -> Dict[str, Any]:
        """
        Extract available EXIF metadata from an image.
        """

        exif_data: Dict[str, Any] = {}

        try:
            raw_exif = image.getexif()

            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))

                # Convert values to strings where necessary so that
                # the result can be safely serialized as JSON.
                try:
                    exif_data[tag_name] = str(value)
                except Exception:
                    exif_data[tag_name] = repr(value)

        except Exception:
            return {}

        return exif_data

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform non-destructive forensic inspection of an image.
        """

        try:
            with Image.open(file_path) as image:

                exif_metadata = self.extract_exif(image)

                return {
                    "analysis_type": "image",
                    "format": image.format,
                    "width": image.width,
                    "height": image.height,
                    "mode": image.mode,
                    "has_exif": bool(exif_metadata),
                    "exif_metadata": exif_metadata,
                    "anomalies": [],
                }

        except FileNotFoundError:
            raise FileNotFoundError(
                f"Evidence image not found: {file_path}"
            )

        except Exception as exc:
            return {
                "analysis_type": "image",
                "format": None,
                "width": None,
                "height": None,
                "mode": None,
                "has_exif": False,
                "exif_metadata": {},
                "anomalies": [
                    f"Unable to analyze image: {str(exc)}"
                ],
            }
