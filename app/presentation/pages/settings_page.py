"""SettingsPage - explicit Save, no auto-save, dotted-key values.

The page only collects/populates values; persistence happens in the caller
(MainWindow -> SettingsUseCase). Target folders support both a native folder
picker and manual path entry (unlimited entries).

# reference pattern
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class SettingsPage(QWidget):
    """Edits the app settings; emits ``save_requested`` with dotted keys."""

    save_requested = pyqtSignal(object)  # dict[str, Any]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        form = QFormLayout()

        self._url = QLineEdit(self)
        form.addRow("Bitwarden server URL:", self._url)

        self._email = QLineEdit(self)
        form.addRow("Email:", self._email)

        self._bw_path = QLineEdit(self)
        self._bw_path.setPlaceholderText("bw")
        form.addRow("bw CLI path:", self._bw_path)

        self._output_folder = QLineEdit(self)
        self._output_folder.setReadOnly(True)
        browse_output = QPushButton("Browse...", self)
        browse_output.clicked.connect(self._pick_output_folder)
        output_row = QHBoxLayout()
        output_row.addWidget(self._output_folder, 1)
        output_row.addWidget(browse_output)
        form.addRow("Output folder:", output_row)

        self._targets = QListWidget(self)
        add_folder = QPushButton("Add folder...", self)
        add_folder.clicked.connect(self._add_target_folder)
        add_path = QPushButton("Add path...", self)
        add_path.clicked.connect(self._add_target_path)
        remove_target = QPushButton("Remove selected", self)
        remove_target.clicked.connect(self._remove_target)
        target_row = QHBoxLayout()
        target_row.addWidget(self._targets, 1)
        target_column = QVBoxLayout()
        target_column.addWidget(add_folder)
        target_column.addWidget(add_path)
        target_column.addWidget(remove_target)
        target_column.addStretch(1)
        target_row.addLayout(target_column)
        form.addRow("Target folders:", target_row)

        self._delete_after_copy = QCheckBox(
            "Delete the source export file after all copies succeeded",
            self,
        )
        form.addRow(self._delete_after_copy)

        self._check_at_startup = QCheckBox(
            "Check for updates at startup",
            self,
        )
        form.addRow(self._check_at_startup)

        self._save_button = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save,
            self,
        )
        self._save_button.clicked.connect(self._on_save)

        self._status = QLabel("", self)
        self._status.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._save_button, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._status)
        layout.addStretch(1)

    def populate(self, values: dict) -> None:
        """Load dotted-key values from ``SettingsUseCase.get_all()``."""
        self._url.setText(str(values.get("bitwarden.url") or ""))
        self._email.setText(str(values.get("bitwarden.email") or ""))
        self._bw_path.setText(str(values.get("bitwarden.bw_path") or ""))
        self._output_folder.setText(str(values.get("output.output_folder") or ""))
        self._targets.clear()
        for folder in values.get("output.target_folders") or []:
            self._targets.addItem(str(folder))
        self._delete_after_copy.setChecked(bool(values.get("output.delete_after_copy")))
        self._check_at_startup.setChecked(bool(values.get("update.check_at_startup")))

    def set_status(self, text: str, *, error: bool = False) -> None:
        self._status.setText(text)
        self._status.setStyleSheet("color: #b00020;" if error else "")

    def _collect(self) -> dict:
        """Current form values as dotted keys (update.token is never collected)."""
        return {
            "bitwarden.url": self._url.text().strip(),
            "bitwarden.email": self._email.text().strip(),
            "bitwarden.bw_path": self._bw_path.text().strip(),
            "output.output_folder": self._output_folder.text().strip(),
            "output.target_folders": [
                self._targets.item(i).text() for i in range(self._targets.count())
            ],
            "output.delete_after_copy": self._delete_after_copy.isChecked(),
            "update.check_at_startup": self._check_at_startup.isChecked(),
        }

    def _on_save(self) -> None:
        self.save_requested.emit(self._collect())

    def _pick_output_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if selected:
            self._output_folder.setText(selected)

    def _add_target_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Choose target folder")
        if selected and selected not in self._target_paths():
            self._targets.addItem(selected)

    def _add_target_path(self) -> None:
        text, ok = QInputDialog.getText(self, "Add target folder", "Folder path:")
        if ok and text and text not in self._target_paths():
            self._targets.addItem(text)

    def _remove_target(self) -> None:
        for item in self._targets.selectedItems():
            self._targets.takeItem(self._targets.row(item))

    def _target_paths(self) -> list[str]:
        return [self._targets.item(i).text() for i in range(self._targets.count())]
