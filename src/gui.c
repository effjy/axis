#include "gui.h"
#include "config.h"
#include "volume.h"
#include "vfs.h"
#include "utils.h"
#include "fuse_mount.h"
#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Forward declarations */
static void on_create_volume_clicked(GtkWidget *widget, gpointer data);
static void on_open_volume_clicked(GtkWidget *widget, gpointer data);
static void on_mount_volume_clicked(GtkWidget *widget, gpointer data);
static void on_unmount_volume_clicked(GtkWidget *widget, gpointer data);
static void on_close_volume_clicked(GtkWidget *widget, gpointer data);
static void on_toggle_password(GtkWidget *widget, gpointer data);
static void on_about_clicked(GtkWidget *widget, gpointer data);
static void on_quit_clicked(GtkWidget *widget, gpointer data);
static GdkPixbuf* load_app_logo(int size);
static void on_browse_clicked(GtkWidget *widget, gpointer data);
static void on_volume_path_changed(GtkWidget *widget, gpointer data);
static void update_telemetry(AppState *app);


/* Progress callback data */
typedef struct {
    GtkWidget *progress_bar;
    GtkWidget *status_label;
    GtkApplication *app;
} ProgressData;

/* Progress callback for volume operations */
static void progress_callback(const char *label, size_t cur, size_t total, void *user_data) {
    ProgressData *data = (ProgressData *)user_data;
    if (!data) return;
    
    double fraction = (total > 0) ? (double)cur / total : 0.0;
    char status_text[256];
    snprintf(status_text, sizeof(status_text), "%s: %.1f%%", label, fraction * 100.0);
    
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(data->progress_bar), fraction);
    gtk_label_set_text(GTK_LABEL(data->status_label), status_text);
    
    while (gtk_events_pending()) gtk_main_iteration();
}

/* Show error dialog */
void show_error_dialog(GtkWidget *parent, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(parent),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_ERROR,
        GTK_BUTTONS_OK,
        "%s", message
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Show info dialog */
void show_info_dialog(GtkWidget *parent, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(parent),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO,
        GTK_BUTTONS_OK,
        "%s", message
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Show warning dialog */
void show_warning_dialog(GtkWidget *parent, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(parent),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_WARNING,
        GTK_BUTTONS_OK,
        "%s", message
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* File chooser dialog */
static char* choose_file(GtkWidget *parent, const char *title, GtkFileChooserAction action) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        title,
        GTK_WINDOW(parent),
        action,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Select", GTK_RESPONSE_ACCEPT,
        NULL
    );
    
    char *filename = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    }
    gtk_widget_destroy(dialog);
    return filename;
}

static void update_telemetry(AppState *app) {
    if (!app) return;
    
    /* 1. Active Volume File */
    if (app->current_volume && app->current_volume->is_open) {
        char *path = app->current_volume->path;
        if (path && *path) {
            char *base = g_path_get_basename(path);
            char *markup = g_strdup_printf("<span font_desc='monospace 10' color='#22D3EE'>%s</span>", base);
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), markup);
            g_free(base);
            g_free(markup);
        } else {
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), "<span color='#6F6F86'>None</span>");
        }
    } else {
        const char *entry_path = gtk_entry_get_text(GTK_ENTRY(app->volume_path_entry));
        if (entry_path && *entry_path) {
            char *base = g_path_get_basename(entry_path);
            char *markup = g_strdup_printf("<span font_desc='monospace 10' color='#6F6F86'>%s (unopened)</span>", base);
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), markup);
            g_free(base);
            g_free(markup);
        } else {
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), "<span color='#6F6F86'>None</span>");
        }
    }
    
    /* 2. Decryption Lock State */
    if (app->current_volume && app->current_volume->is_open) {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_lock), "<span color='#34D399'>●</span> <span color='#34D399' weight='bold'>UNLOCKED</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_lock), "<span color='#FB7185'>●</span> <span color='#FB7185' weight='bold'>LOCKED</span>");
    }
    
    /* 3. Mount Status */
    if (app->current_volume && app->current_volume->is_open && app->current_volume->vfs.is_mounted) {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_mount), "<span color='#34D399'>●</span> <span color='#34D399' weight='bold'>ACTIVE</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_mount), "<span color='#6F6F86'>●</span> <span color='#6F6F86' weight='bold'>INACTIVE</span>");
    }
}

static void on_browse_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    char *path = choose_file(app->window, "Select Encrypted Volume File", GTK_FILE_CHOOSER_ACTION_OPEN);
    if (path) {
        gtk_entry_set_text(GTK_ENTRY(app->volume_path_entry), path);
        g_free(path);
    }
}

static void on_volume_path_changed(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    update_telemetry(app);
}

/* Create volume callback */
static void on_create_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    const char *path = gtk_entry_get_text(GTK_ENTRY(app->volume_path_entry));
    const char *size_str = gtk_entry_get_text(GTK_ENTRY(app->volume_size_entry));
    const char *password = gtk_entry_get_text(GTK_ENTRY(app->password_entry));

    if (!path || !*path) {
        show_error_dialog(app->window, "Please enter a volume file path.");
        return;
    }
    if (!size_str || !*size_str) {
        show_error_dialog(app->window, "Please enter volume size in MB.");
        return;
    }
    if (!password || !*password) {
        show_error_dialog(app->window, "Please enter a password.");
        return;
    }

    /* Use strtol so we can detect non-numeric input and overflow */
    char *end = NULL;
    long size_mb_l = strtol(size_str, &end, 10);
    if (!end || *end != '\0' || size_mb_l <= 0) {
        show_error_dialog(app->window, "Please enter a valid numeric volume size.");
        return;
    }
    if (size_mb_l < 10) {
        show_error_dialog(app->window, "Volume size must be at least 10 MB.");
        return;
    }
    if (size_mb_l > 1024 * 1024) {  /* cap at 1 TiB */
        show_error_dialog(app->window, "Volume size must not exceed 1048576 MB (1 TiB).");
        return;
    }
    size_t size_mb = (size_t)size_mb_l;

    gtk_label_set_text(GTK_LABEL(app->status_label), "Creating volume...");

    ProgressData prog_data = {
        .progress_bar = app->progress_bar,
        .status_label = app->status_label
    };

    int result = volume_create(path, size_mb, password, progress_callback, &prog_data);

    /* Wipe password from GTK widget memory immediately after use */
    gtk_entry_set_text(GTK_ENTRY(app->password_entry), "");

    if (result == 0) {
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 1.0);
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume created successfully!");
        show_info_dialog(app->window, "Volume created successfully!");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume creation failed!");
        show_error_dialog(app->window, "Failed to create volume. Check permissions and try again.");
    }
    update_telemetry(app);
}

/* Open volume callback */
static void on_open_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    char *path = choose_file(app->window, "Select Volume File", GTK_FILE_CHOOSER_ACTION_OPEN);
    if (!path) {
        return;
    }

    const char *password = gtk_entry_get_text(GTK_ENTRY(app->password_entry));
    if (!password || !*password) {
        show_error_dialog(app->window, "Please enter a password.");
        g_free(path);
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Opening volume...");

    if (app->current_volume) {
        if (app->current_volume->is_open) {
            if (app->current_volume->vfs.is_mounted) {
                stop_fuse_mount(app->current_volume);
                volume_unmount(app->current_volume);
            }
            volume_close(app->current_volume, NULL, NULL);
            free(app->current_volume);
        }
    }

    app->current_volume = malloc(sizeof(volume_context_t));
    memset(app->current_volume, 0, sizeof(volume_context_t));

    if (lock_sensitive(app->current_volume, sizeof(volume_context_t)) != 0) {
        show_warning_dialog(app->window, 
            "Warning: Memory locking failed.\n\n"
            "The master key may be swapped to disk. Run as root or increase memlock limits to ensure maximum security.");
    }

    /* Set up progress callback */
    ProgressData progress_data = {
        .progress_bar = app->progress_bar,
        .status_label = app->status_label,
        .app = GTK_APPLICATION(gtk_window_get_application(GTK_WINDOW(app->window)))
    };

    /* Ensure UI updates are processed before opening volume */
    gtk_label_set_text(GTK_LABEL(app->status_label), "Preparing to open volume...");
    /* Process all pending events to ensure dialog cleanup */
    while (gtk_events_pending()) gtk_main_iteration();
    /* Force a UI update cycle */
    GdkDisplay *display = gdk_display_get_default();
    if (display) {
        gdk_display_flush(display);
    }

    int result = volume_open(path, password, app->current_volume, progress_callback, &progress_data);

    /* Wipe password from GTK widget memory immediately after use */
    gtk_entry_set_text(GTK_ENTRY(app->password_entry), "");

    if (result == 0) {
        gtk_entry_set_text(GTK_ENTRY(app->volume_path_entry), path);
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume opened successfully!");
        show_info_dialog(app->window, "Volume opened! Click 'Mount' to access files.");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to open volume!");
        /* Distinguish Argon2 memory failure from wrong password.
         * derive_master_key uses 1 GiB of RAM; on low-memory systems
         * crypto_pwhash returns -1 before even comparing the password. */
        show_error_dialog(app->window,
            "Failed to open volume.\n\n"
            "This can mean:\n"
            "  \xe2\x80\xa2 Wrong password\n"
            "  \xe2\x80\xa2 Corrupted volume file\n"
            "  \xe2\x80\xa2 Insufficient RAM for Argon2 (needs ~1 GB free)");
        free(app->current_volume);
        app->current_volume = NULL;
    }

    g_free(path);
    update_telemetry(app);
}

/* Mount volume callback */static void on_check_space_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    if (!app->current_volume || !app->current_volume->vfs.is_mounted) return;
    
    uint64_t total = (uint64_t)app->current_volume->vfs.header.total_sectors * VFS_SECTOR_SIZE;
    uint64_t used = (uint64_t)app->current_volume->vfs.header.used_sectors * VFS_SECTOR_SIZE;
    uint64_t free_bytes = total > used ? total - used : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Total space: %.2f MB\nUsed space: %.2f MB\nFree space: %.2f MB",
             (double)total / (1024*1024), (double)used / (1024*1024), (double)free_bytes / (1024*1024));
    show_info_dialog(app->window, msg);
}

static void on_mount_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    if (!app->current_volume || !app->current_volume->is_open) {
        show_error_dialog(app->window, "No volume is currently open.");
        return;
    }

    if (app->current_volume->vfs.is_mounted) {
        stop_fuse_mount(app->current_volume);
        volume_unmount(app->current_volume);
    }
    if (0) {
        show_error_dialog(app->window, "Volume is already mounted.");
        return;
    }

    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Select Mount Directory",
        GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Mount", GTK_RESPONSE_ACCEPT,
        NULL
    );
    
    char *mount_dir = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        mount_dir = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    }
    gtk_widget_destroy(dialog);
    
    if (!mount_dir) {
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Mounting volume...");

    int result = volume_mount(app->current_volume);
    if (result == 0) {
        if (start_fuse_mount(app->current_volume, mount_dir) != 0) {
            volume_unmount(app->current_volume);
            show_error_dialog(app->window, "Failed to start FUSE daemon.");
        } else {
            gtk_label_set_text(GTK_LABEL(app->status_label), "Volume mounted via FUSE!");
            if (app->btn_check_space) gtk_widget_set_sensitive(app->btn_check_space, TRUE);
            show_info_dialog(app->window, "Volume mounted successfully via FUSE!");
        }
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to mount volume!");
        show_error_dialog(app->window, "Failed to mount volume. The filesystem may be corrupted.");
    }
    g_free(mount_dir);
    update_telemetry(app);
}

/* Unmount volume callback */
static void on_unmount_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    if (!app->current_volume || !app->current_volume->vfs.is_mounted) {
        show_error_dialog(app->window, "No volume is currently mounted.");
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Unmounting volume...");

    stop_fuse_mount(app->current_volume);
    int result = volume_unmount(app->current_volume);
    if (app->btn_check_space) gtk_widget_set_sensitive(app->btn_check_space, FALSE);
    
    if (result == 0) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume unmounted!");
        show_info_dialog(app->window, "Volume unmounted successfully!");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to unmount volume!");
        show_error_dialog(app->window, "Failed to unmount volume.");
    }
    update_telemetry(app);
}

/* Close volume callback */
static void on_close_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    if (!app->current_volume || !app->current_volume->is_open) {
        show_error_dialog(app->window, "No volume is currently open.");
        return;
    }

    if (app->current_volume->vfs.is_mounted) {
        stop_fuse_mount(app->current_volume);
        volume_unmount(app->current_volume);
        if (app->btn_check_space) gtk_widget_set_sensitive(app->btn_check_space, FALSE);
    }
    if (0) {
        show_error_dialog(app->window, "Please unmount the volume before closing.");
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Closing volume...");

    /* Set up progress callback */
    ProgressData progress_data = {
        .progress_bar = app->progress_bar,
        .status_label = app->status_label,
        .app = GTK_APPLICATION(gtk_window_get_application(GTK_WINDOW(app->window)))
    };

    int result = volume_close(app->current_volume, progress_callback, &progress_data);

    if (result == 0) {
        free(app->current_volume);
        app->current_volume = NULL;
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume closed!");

        show_info_dialog(app->window, "Volume closed successfully!");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to close volume!");
        show_error_dialog(app->window, "Failed to close volume.");
    }
    update_telemetry(app);
}

/* Toggle password visibility */
static void on_toggle_password(GtkWidget *widget, gpointer data) {
    AppState *app = (AppState *)data;
    app->show_password = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
    gtk_entry_set_visibility(GTK_ENTRY(app->password_entry), app->show_password);
}

/* Helper to add a feature row to the about dialog */
static void add_feature_row(GtkWidget *box, const char *title, const char *desc, const char *icon_symbol) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(row), 10);
    
    GtkWidget *icon_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(icon_label), g_strdup_printf("<span size='xx-large'>%s</span>", icon_symbol));
    gtk_widget_set_valign(icon_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(row), icon_label, FALSE, FALSE, 0);
    
    GtkWidget *text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    
    GtkWidget *title_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title_label), g_strdup_printf("<span weight='bold' size='large' color='#A78BFA'>%s</span>", title));
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0);
    gtk_box_pack_start(GTK_BOX(text_vbox), title_label, FALSE, FALSE, 0);
    
    GtkWidget *desc_label = gtk_label_new(desc);
    gtk_label_set_line_wrap(GTK_LABEL(desc_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(desc_label), 0.0);
    gtk_label_set_max_width_chars(GTK_LABEL(desc_label), 60);
    gtk_box_pack_start(GTK_BOX(text_vbox), desc_label, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(row), text_vbox, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 5);
    
    /* Add a subtle separator line */
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(sep, 0.2);
    gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
}

/* Revamped About dialog */
static void on_about_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    
    GtkWidget *dialog = gtk_dialog_new_with_buttons("About Axis",
                                                    GTK_WINDOW(app->window),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "_Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    
    gtk_window_set_default_size(GTK_WINDOW(dialog), 600, 700);
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 12);
    gtk_container_add(GTK_CONTAINER(content_area), main_vbox);
    
    /* Header Section */
    GdkPixbuf *logo = load_app_logo(130);
    if (logo) {
        GtkWidget *logo_img = gtk_image_new_from_pixbuf(logo);
        gtk_box_pack_start(GTK_BOX(main_vbox), logo_img, FALSE, FALSE, 0);
        g_object_unref(logo);
    }
    
    GtkWidget *name_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(name_label), "<span size='x-large' weight='bold' color='#F4F4F8'>AXIS</span>  <span size='large' color='#8E8EA8'>Encrypted Disk Manager</span>");
    gtk_box_pack_start(GTK_BOX(main_vbox), name_label, FALSE, FALSE, 0);
    
    GtkWidget *ver_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(ver_label), g_strdup_printf("<span color='#22D3EE' weight='bold' letter_spacing='2000'>VERSION %s</span>", APP_VERSION));
    gtk_box_pack_start(GTK_BOX(main_vbox), ver_label, FALSE, FALSE, 2);
    
    GtkWidget *sep_top = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_vbox), sep_top, FALSE, FALSE, 6);
    
    /* Scrollable Features Section */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scrolled, -1, 300);
    gtk_box_pack_start(GTK_BOX(main_vbox), scrolled, TRUE, TRUE, 0);
    
    GtkWidget *feature_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(scrolled), feature_box);
    
    /* Best Features */
    add_feature_row(feature_box, "Uniform 256-bit Post-Quantum Shield", 
        "Engineered for the future. While standard tools offer only 128-bit quantum security, "
        "Axis provides a uniform 256-bit security margin across all layers.", "\xf0\x9f\x9b\xa1\xef\xb8\x8f"); /* Shield */

    add_feature_row(feature_box, "Absolute Plausible Deniability", 
        "Volumes are IND-RND compliant. To forensic analysis, your data is mathematically "
        "indistinguishable from random noise. No signatures, no headers, no leaks.", "\xf0\x9f\x8c\x91"); /* New Moon */
    add_feature_row(feature_box, "Hybrid Defense Architecture", 
        "A multi-layered cryptographic shield combining Kyber-1024 and X448. "
        "Protected against both today's supercomputers and tomorrow's quantum threats.", "\xf0\x9f\xa7\xac"); /* DNA */

    add_feature_row(feature_box, "ASIC-Resistant Argon2id",
        "Armed with 1 GB RAM-locked password hashing. Makes GPU/ASIC-based "
        "brute-force attacks astronomically expensive and inefficient.", "\xf0\x9f\x94\x92"); /* Locked */

    /* Footer / Author */
    GtkWidget *footer_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(footer_label), 
        "<span size='small' color='#6F6F86'>Created by Jean-Francois Lachance-Caumartin (Effjy)\n"
        "Contact: effjy@protonmail.com</span>");
    gtk_label_set_justify(GTK_LABEL(footer_label), GTK_JUSTIFY_CENTER);
    gtk_box_pack_start(GTK_BOX(main_vbox), footer_label, FALSE, FALSE, 10);
    
    /* Using global CSS defined in on_activate */
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Quit callback */
static void on_quit_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    
    if (app->current_volume) {
        if (app->current_volume->is_open) {
            if (app->current_volume->vfs.is_mounted) {
                stop_fuse_mount(app->current_volume);
                volume_unmount(app->current_volume);
            }
            volume_close(app->current_volume, NULL, NULL);
            free(app->current_volume);
            app->current_volume = NULL;
        }
    }
    
    gtk_window_close(GTK_WINDOW(app->window));
}

/* Helper to load the app logo with fallbacks */
static GdkPixbuf* load_app_logo(int size) {
    GdkPixbuf *logo = NULL;
    GError *error = NULL;
    
    char *cwd = g_get_current_dir();
    char *path_logo1 = g_build_filename(cwd, "axis_logo.png", NULL);
    char *path_logo2 = g_build_filename(cwd, "axis_logo.png", NULL);
    char *path1 = g_build_filename(cwd, "axis_logo.png", NULL);
    char *path2 = g_build_filename(cwd, "axis_logo.png", NULL);
    
    const char *paths[] = {
        path_logo1,
        path_logo2,
        "axis_logo.png",
        "axis_logo.png",
        "/usr/share/axis/axis_logo.png",
        "/usr/local/share/axis/axis_logo.png",
        "/usr/share/icons/hicolor/64x64/apps/axis_logo.png",
        path1,
        path2,
        "axis_logo.png",
        "axis_logo.png",
        "axis_logo.png",
        NULL
    };
    
    for (int i = 0; paths[i] != NULL; i++) {
        if (g_file_test(paths[i], G_FILE_TEST_EXISTS)) {
            logo = gdk_pixbuf_new_from_file_at_scale(paths[i], size, size, TRUE, &error);
            if (logo) break;
            if (error) {
                g_error_free(error);
                error = NULL;
            }
        }
    }
    
    g_free(cwd);
    g_free(path_logo1);
    g_free(path_logo2);
    g_free(path1);
    g_free(path2);
    
    return logo;
}




typedef struct {
    GtkWidget *splash;
    GtkWidget *main_window;
    GtkWidget *progress;
    int ticks;
} SplashTimeoutData;

static gboolean on_splash_timeout(gpointer data) {
    SplashTimeoutData *std = (SplashTimeoutData *)data;
    std->ticks++;
    
    /* 25 ticks of 100ms = 2.5 seconds */
    double fraction = (double)std->ticks / 25.0;
    if (fraction > 1.0) fraction = 1.0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(std->progress), fraction);
    
    if (std->ticks >= 25) {
        /* Destroy splash window */
        gtk_widget_destroy(std->splash);
        
        /* Show main window */
        gtk_widget_show_all(std->main_window);
        
        g_free(std);
        return FALSE; /* Stop timeout */
    }
    return TRUE; /* Continue timeout */
}

/* Activate callback - build GUI */
static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    AppState *app_state = g_malloc(sizeof(AppState));
    app_state->show_password = 0;
    app_state->current_volume = NULL;

    /* ====================================================================
     * Axis "Aurora" design system
     * Deep-obsidian canvas, glassy layered cards, and a signature
     * violet -> cyan accent gradient used for brand + primary actions.
     * ==================================================================== */
    GtkCssProvider *css_provider = gtk_css_provider_new();
    const gchar *css_data =
        /* ---- Global canvas ---- */
        "window, dialog {\n"
        "    background-color: #08080C;\n"
        "    color: #ECECF1;\n"
        "    font-family: 'Inter', 'Roboto', 'Segoe UI', sans-serif;\n"
        "    font-size: 12px;\n"
        "}\n"
        /* ---- Title bar ---- */
        "headerbar {\n"
        "    background: linear-gradient(180deg, #121219, #0B0B11);\n"
        "    border-bottom: 1px solid rgba(139,92,246,0.25);\n"
        "    box-shadow: 0 1px 0 rgba(34,211,238,0.10);\n"
        "    min-height: 38px;\n"
        "}\n"
        "headerbar .title {\n"
        "    font-weight: 800;\n"
        "    letter-spacing: 3px;\n"
        "    color: #F4F4F8;\n"
        "}\n"
        "headerbar .subtitle {\n"
        "    color: #8E8EA8;\n"
        "    letter-spacing: 1px;\n"
        "}\n"
        /* ---- Structural panes ---- */
        ".sidebar {\n"
        "    background: linear-gradient(180deg, #0A0A10, #060609);\n"
        "    border-right: 1px solid rgba(139,92,246,0.18);\n"
        "}\n"
        ".main-content {\n"
        "    background-color: #08080C;\n"
        "}\n"
        /* ---- Glass cards ---- */
        ".card {\n"
        "    background: linear-gradient(160deg, #17171F, #101016);\n"
        "    border: 1px solid rgba(255,255,255,0.06);\n"
        "    border-radius: 14px;\n"
        "    padding: 14px;\n"
        "    box-shadow: 0 6px 18px rgba(0,0,0,0.45);\n"
        "}\n"
        ".card:hover {\n"
        "    border: 1px solid rgba(34,211,238,0.22);\n"
        "}\n"
        ".card-title {\n"
        "    font-size: 10px;\n"
        "    font-weight: 800;\n"
        "    color: #A78BFA;\n"
        "    letter-spacing: 2.5px;\n"
        "    margin-bottom: 6px;\n"
        "}\n"
        /* ---- Brand block ---- */
        ".brand-title {\n"
        "    font-weight: 900;\n"
        "    font-size: 22px;\n"
        "    color: #F4F4F8;\n"
        "    letter-spacing: 8px;\n"
        "    text-shadow: 0 0 16px rgba(139,92,246,0.55);\n"
        "}\n"
        ".brand-subtitle {\n"
        "    font-size: 9px;\n"
        "    font-weight: 700;\n"
        "    color: #22D3EE;\n"
        "    letter-spacing: 3px;\n"
        "}\n"
        /* ---- Telemetry ---- */
        ".telemetry-label {\n"
        "    font-size: 10px;\n"
        "    color: #6F6F86;\n"
        "    font-weight: 800;\n"
        "    letter-spacing: 1px;\n"
        "}\n"
        ".telemetry-value {\n"
        "    font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;\n"
        "    font-size: 11px;\n"
        "    color: #ECECF1;\n"
        "}\n"
        /* ---- Inputs ---- */
        "entry {\n"
        "    background-color: #0B0B11;\n"
        "    color: #F4F4F8;\n"
        "    border: 1px solid rgba(255,255,255,0.08);\n"
        "    border-radius: 9px;\n"
        "    padding: 8px 12px;\n"
        "    caret-color: #22D3EE;\n"
        "    transition: all 220ms ease;\n"
        "}\n"
        "entry:focus {\n"
        "    border-color: #22D3EE;\n"
        "    box-shadow: 0 0 0 3px rgba(34,211,238,0.18);\n"
        "    background-color: #0D0D14;\n"
        "}\n"
        "entry image {\n"
        "    color: #6F6F86;\n"
        "}\n"
        /* ---- Buttons (default = ghost) ---- */
        "button {\n"
        "    background: linear-gradient(180deg, #1B1B24, #141419);\n"
        "    color: #ECECF1;\n"
        "    border: 1px solid rgba(255,255,255,0.08);\n"
        "    border-radius: 9px;\n"
        "    padding: 7px 12px;\n"
        "    font-weight: 700;\n"
        "    transition: all 200ms ease;\n"
        "}\n"
        "button:hover {\n"
        "    background: linear-gradient(180deg, #232330, #181820);\n"
        "    border-color: rgba(34,211,238,0.55);\n"
        "    color: #FFFFFF;\n"
        "}\n"
        "button:active {\n"
        "    background: #2A2A38;\n"
        "}\n"
        "button:disabled {\n"
        "    color: #50505F;\n"
        "    border-color: rgba(255,255,255,0.04);\n"
        "    background: #101016;\n"
        "}\n"
        "button image { -gtk-icon-transform: none; }\n"
        /* ---- Primary action (violet -> cyan) ---- */
        ".btn-cyan {\n"
        "    background: linear-gradient(120deg, #8B5CF6 0%, #22D3EE 100%);\n"
        "    color: #08080C;\n"
        "    border: none;\n"
        "    font-weight: 900;\n"
        "    letter-spacing: 0.5px;\n"
        "    box-shadow: 0 4px 16px rgba(34,211,238,0.30);\n"
        "}\n"
        ".btn-cyan:hover {\n"
        "    background: linear-gradient(120deg, #9D74FF 0%, #3FE0F5 100%);\n"
        "    color: #000000;\n"
        "    box-shadow: 0 6px 22px rgba(139,92,246,0.45);\n"
        "}\n"
        ".btn-cyan:active { background: #22D3EE; }\n"
        /* ---- Destructive action ---- */
        ".btn-red {\n"
        "    background: rgba(244,63,94,0.08);\n"
        "    color: #FB7185;\n"
        "    border: 1px solid rgba(244,63,94,0.55);\n"
        "}\n"
        ".btn-red:hover {\n"
        "    background: linear-gradient(180deg, #F43F5E, #BE123C);\n"
        "    color: #FFFFFF;\n"
        "    border-color: #F43F5E;\n"
        "    box-shadow: 0 4px 16px rgba(244,63,94,0.35);\n"
        "}\n"
        /* ---- Progress ---- */
        "progressbar > trough {\n"
        "    background-color: #050507;\n"
        "    border-radius: 6px;\n"
        "    border: 1px solid rgba(255,255,255,0.06);\n"
        "    min-height: 8px;\n"
        "}\n"
        "progressbar > trough > progress {\n"
        "    background: linear-gradient(90deg, #8B5CF6, #22D3EE);\n"
        "    border-radius: 6px;\n"
        "    box-shadow: 0 0 12px rgba(34,211,238,0.55);\n"
        "}\n"
        /* ---- Status console ---- */
        "label.status {\n"
        "    font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;\n"
        "    font-size: 11px;\n"
        "    color: #22D3EE;\n"
        "}\n"
        "checkbutton { color: #8E8EA8; font-size: 11px; }\n"
        "checkbutton check {\n"
        "    background: #0B0B11;\n"
        "    border: 1px solid rgba(255,255,255,0.12);\n"
        "    border-radius: 5px;\n"
        "}\n"
        "checkbutton check:checked {\n"
        "    background: linear-gradient(120deg, #8B5CF6, #22D3EE);\n"
        "    border-color: #22D3EE;\n"
        "}\n"
        "separator { background-color: rgba(255,255,255,0.07); min-height: 1px; min-width: 1px; }\n"
        /* ---- Splash ---- */
        ".splash-window {\n"
        "    background: radial-gradient(circle at 50% 30%, #15151F 0%, #08080C 70%);\n"
        "    border: 1px solid rgba(139,92,246,0.55);\n"
        "    border-radius: 18px;\n"
        "    box-shadow: 0 0 40px rgba(34,211,238,0.25);\n"
        "}\n"
        ".splash-loading {\n"
        "    font-size: 1.05em;\n"
        "    font-weight: 800;\n"
        "    color: #22D3EE;\n"
        "    letter-spacing: 4px;\n"
        "    font-family: 'Inter', sans-serif;\n"
        "    text-shadow: 0 0 14px rgba(34,211,238,0.6);\n"
        "}\n"
        ".splash-tagline {\n"
        "    font-size: 9px;\n"
        "    font-weight: 700;\n"
        "    color: #6F6F86;\n"
        "    letter-spacing: 3px;\n"
        "}";

    gtk_css_provider_load_from_data(css_provider, css_data, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                                              GTK_STYLE_PROVIDER(css_provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    /* Main window */
    app_state->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(app_state->window), APP_TITLE);
    gtk_window_set_default_size(GTK_WINDOW(app_state->window), 880, 480);
    
    GdkDisplay *display = gdk_display_get_default();
    if (display) {
        GdkMonitor *monitor = gdk_display_get_primary_monitor(display);
        if (!monitor) {
            monitor = gdk_display_get_monitor(display, 0);
        }
        if (monitor) {
            GdkRectangle geometry;
            gdk_monitor_get_geometry(monitor, &geometry);
            gint screen_width = geometry.width;
            gint x = (screen_width - 880) / 2;
            gtk_window_move(GTK_WINDOW(app_state->window), x, -16);
        }
    }

    /* Set taskbar icon */
    GdkPixbuf *icon = load_app_logo(64);
    if (icon) {
        gtk_window_set_icon(GTK_WINDOW(app_state->window), icon);
        g_object_unref(icon);
    }

    /* Modern HeaderBar */
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Axis");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "v10.0.0 \xe2\x80\xa2 Secure Volume Manager");
    gtk_window_set_titlebar(GTK_WINDOW(app_state->window), header);

    /* Main layout container (Horizontal) */
    GtkWidget *main_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_add(GTK_CONTAINER(app_state->window), main_hbox);

    /* --- Sidebar Pane --- */
    GtkWidget *sidebar_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_size_request(sidebar_vbox, 260, -1);
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar_vbox), "sidebar");
    gtk_container_set_border_width(GTK_CONTAINER(sidebar_vbox), 12);
    gtk_box_pack_start(GTK_BOX(main_hbox), sidebar_vbox, FALSE, FALSE, 0);

    /* Brand Header */
    GtkWidget *brand_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_halign(brand_box, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), brand_box, FALSE, FALSE, 2);

    GtkWidget *logo_img = NULL;
    GdkPixbuf *logo_pb = load_app_logo(140);
    if (logo_pb) {
        logo_img = gtk_image_new_from_pixbuf(logo_pb);
        g_object_unref(logo_pb);
    } else {
        logo_img = gtk_image_new_from_icon_name("applications-system", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(brand_box), logo_img, FALSE, FALSE, 0);

    GtkWidget *lbl_brand_title = gtk_label_new("AXIS");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_brand_title), "brand-title");
    gtk_box_pack_start(GTK_BOX(brand_box), lbl_brand_title, FALSE, FALSE, 0);

    GtkWidget *lbl_brand_subtitle = gtk_label_new("ENCRYPTED DISK MANAGER");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_brand_subtitle), "brand-subtitle");
    gtk_box_pack_start(GTK_BOX(brand_box), lbl_brand_subtitle, FALSE, FALSE, 0);

    /* Separator */
    GtkWidget *sep_sidebar = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(sep_sidebar, 0.2);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), sep_sidebar, FALSE, FALSE, 4);

    /* Telemetry Card */
    GtkWidget *telemetry_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(telemetry_card), "card");
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), telemetry_card, FALSE, FALSE, 0);

    GtkWidget *lbl_telem_title = gtk_label_new("SYSTEM TELEMETRY");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_telem_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_telem_title), 0.0);
    gtk_box_pack_start(GTK_BOX(telemetry_card), lbl_telem_title, FALSE, FALSE, 0);

    GtkWidget *telem_grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(telem_grid), 8);
    gtk_grid_set_row_spacing(GTK_GRID(telem_grid), 4);
    gtk_box_pack_start(GTK_BOX(telemetry_card), telem_grid, TRUE, TRUE, 0);

    // Row 0: Volume Path
    GtkWidget *lbl_path_tag = gtk_label_new("VOLUME:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_path_tag), "telemetry-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_path_tag), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), lbl_path_tag, 0, 0, 1, 1);

    app_state->lbl_telemetry_path = gtk_label_new("None");
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->lbl_telemetry_path), "telemetry-value");
    gtk_label_set_xalign(GTK_LABEL(app_state->lbl_telemetry_path), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(app_state->lbl_telemetry_path), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(app_state->lbl_telemetry_path, TRUE);
    gtk_grid_attach(GTK_GRID(telem_grid), app_state->lbl_telemetry_path, 1, 0, 1, 1);

    // Row 1: Crypto state
    GtkWidget *lbl_lock_tag = gtk_label_new("DECRYPT:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_lock_tag), "telemetry-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_lock_tag), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), lbl_lock_tag, 0, 1, 1, 1);

    app_state->lbl_telemetry_lock = gtk_label_new("LOCKED");
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->lbl_telemetry_lock), "telemetry-value");
    gtk_label_set_xalign(GTK_LABEL(app_state->lbl_telemetry_lock), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), app_state->lbl_telemetry_lock, 1, 1, 1, 1);

    // Row 2: Mount status
    GtkWidget *lbl_mount_tag = gtk_label_new("MOUNT:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_mount_tag), "telemetry-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_mount_tag), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), lbl_mount_tag, 0, 2, 1, 1);

    app_state->lbl_telemetry_mount = gtk_label_new("INACTIVE");
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->lbl_telemetry_mount), "telemetry-value");
    gtk_label_set_xalign(GTK_LABEL(app_state->lbl_telemetry_mount), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), app_state->lbl_telemetry_mount, 1, 2, 1, 1);

    /* Security Credentials Card */
    GtkWidget *security_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_style_context_add_class(gtk_widget_get_style_context(security_card), "card");
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), security_card, FALSE, FALSE, 0);

    GtkWidget *lbl_sec_title = gtk_label_new("CREDENTIALS");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_sec_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_sec_title), 0.0);
    gtk_box_pack_start(GTK_BOX(security_card), lbl_sec_title, FALSE, FALSE, 0);

    app_state->password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(app_state->password_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(app_state->password_entry), '*');
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state->password_entry), "Password");
    gtk_box_pack_start(GTK_BOX(security_card), app_state->password_entry, FALSE, FALSE, 2);

    app_state->show_password_check = gtk_check_button_new_with_label("Reveal characters");
    g_signal_connect(app_state->show_password_check, "toggled", G_CALLBACK(on_toggle_password), app_state);
    gtk_box_pack_start(GTK_BOX(security_card), app_state->show_password_check, FALSE, FALSE, 0);

    /* Sidebar Spacer */
    GtkWidget *sidebar_spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), sidebar_spacer, TRUE, TRUE, 0);

    /* Sidebar Footer Buttons */
    GtkWidget *sidebar_footer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(sidebar_footer, GTK_ALIGN_FILL);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), sidebar_footer, FALSE, FALSE, 4);

    GtkWidget *about_btn = gtk_button_new_with_label("About");
    gtk_button_set_image(GTK_BUTTON(about_btn), gtk_image_new_from_icon_name("help-about", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(about_btn), TRUE);
    gtk_widget_set_hexpand(about_btn, TRUE);
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(sidebar_footer), about_btn, TRUE, TRUE, 0);

    GtkWidget *quit_btn = gtk_button_new_with_label("Exit");
    gtk_button_set_image(GTK_BUTTON(quit_btn), gtk_image_new_from_icon_name("application-exit", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(quit_btn), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(quit_btn), "btn-red");
    gtk_widget_set_hexpand(quit_btn, TRUE);
    g_signal_connect(quit_btn, "clicked", G_CALLBACK(on_quit_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(sidebar_footer), quit_btn, TRUE, TRUE, 0);


    /* --- Main Content Pane --- */
    GtkWidget *content_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(content_vbox), "main-content");
    gtk_container_set_border_width(GTK_CONTAINER(content_vbox), 16);
    gtk_box_pack_start(GTK_BOX(main_hbox), content_vbox, TRUE, TRUE, 0);

    /* Volume Target File Card */
    GtkWidget *target_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(target_card), "card");
    gtk_box_pack_start(GTK_BOX(content_vbox), target_card, FALSE, FALSE, 0);

    GtkWidget *lbl_target_title = gtk_label_new("ENCRYPTED VOLUME FILE");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_target_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_target_title), 0.0);
    gtk_box_pack_start(GTK_BOX(target_card), lbl_target_title, FALSE, FALSE, 0);

    GtkWidget *target_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(target_card), target_hbox, TRUE, TRUE, 0);

    app_state->volume_path_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state->volume_path_entry), "Select location for volume file...");
    gtk_widget_set_hexpand(app_state->volume_path_entry, TRUE);
    g_signal_connect(app_state->volume_path_entry, "changed", G_CALLBACK(on_volume_path_changed), app_state);
    gtk_box_pack_start(GTK_BOX(target_hbox), app_state->volume_path_entry, TRUE, TRUE, 0);

    GtkWidget *btn_browse = gtk_button_new_from_icon_name("folder-open", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(btn_browse, "Browse volume file...");
    g_signal_connect(btn_browse, "clicked", G_CALLBACK(on_browse_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(target_hbox), btn_browse, FALSE, FALSE, 0);


    /* Middle operations section (Side-by-side Cards) */
    GtkWidget *ops_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(ops_hbox), TRUE);
    gtk_box_pack_start(GTK_BOX(content_vbox), ops_hbox, TRUE, TRUE, 0);

    /* Volume Control Card */
    GtkWidget *ctrl_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctrl_card), "card");
    gtk_box_pack_start(GTK_BOX(ops_hbox), ctrl_card, TRUE, TRUE, 0);

    GtkWidget *lbl_ctrl_title = gtk_label_new("VOLUME CONTROL");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_ctrl_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_ctrl_title), 0.0);
    gtk_box_pack_start(GTK_BOX(ctrl_card), lbl_ctrl_title, FALSE, FALSE, 0);

    GtkWidget *btn_row1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(btn_row1), TRUE);
    gtk_box_pack_start(GTK_BOX(ctrl_card), btn_row1, TRUE, TRUE, 0);

    GtkWidget *open_btn = gtk_button_new_with_label("Open");
    gtk_button_set_image(GTK_BUTTON(open_btn), gtk_image_new_from_icon_name("document-open", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(open_btn), TRUE);
    g_signal_connect(open_btn, "clicked", G_CALLBACK(on_open_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row1), open_btn, TRUE, TRUE, 0);

    GtkWidget *close_btn = gtk_button_new_with_label("Close");
    gtk_button_set_image(GTK_BUTTON(close_btn), gtk_image_new_from_icon_name("window-close", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(close_btn), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(close_btn), "btn-red");
    g_signal_connect(close_btn, "clicked", G_CALLBACK(on_close_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row1), close_btn, TRUE, TRUE, 0);

    GtkWidget *btn_row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(btn_row2), TRUE);
    gtk_box_pack_start(GTK_BOX(ctrl_card), btn_row2, TRUE, TRUE, 0);

    GtkWidget *mount_btn = gtk_button_new_with_label("Mount");
    gtk_button_set_image(GTK_BUTTON(mount_btn), gtk_image_new_from_icon_name("drive-harddisk", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(mount_btn), TRUE);
    g_signal_connect(mount_btn, "clicked", G_CALLBACK(on_mount_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row2), mount_btn, TRUE, TRUE, 0);

    GtkWidget *unmount_btn = gtk_button_new_with_label("Unmount");
    gtk_button_set_image(GTK_BUTTON(unmount_btn), gtk_image_new_from_icon_name("media-eject", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(unmount_btn), TRUE);
    g_signal_connect(unmount_btn, "clicked", G_CALLBACK(on_unmount_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row2), unmount_btn, TRUE, TRUE, 0);

    app_state->btn_check_space = gtk_button_new_with_label("Storage Status");
    gtk_button_set_image(GTK_BUTTON(app_state->btn_check_space), gtk_image_new_from_icon_name("dialog-information", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(app_state->btn_check_space), TRUE);
    gtk_widget_set_sensitive(app_state->btn_check_space, FALSE);
    g_signal_connect(app_state->btn_check_space, "clicked", G_CALLBACK(on_check_space_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(ctrl_card), app_state->btn_check_space, TRUE, TRUE, 0);


    /* New Volume Creator Card */
    GtkWidget *create_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(create_card), "card");
    gtk_box_pack_start(GTK_BOX(ops_hbox), create_card, TRUE, TRUE, 0);

    GtkWidget *lbl_create_title = gtk_label_new("NEW VOLUME CREATION");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_create_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_create_title), 0.0);
    gtk_box_pack_start(GTK_BOX(create_card), lbl_create_title, FALSE, FALSE, 0);

    GtkWidget *lbl_size_desc = gtk_label_new("Specify target size in MB:");
    gtk_widget_set_halign(lbl_size_desc, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(create_card), lbl_size_desc, FALSE, FALSE, 2);

    app_state->volume_size_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state->volume_size_entry), "Size (MB)");
    gtk_box_pack_start(GTK_BOX(create_card), app_state->volume_size_entry, FALSE, FALSE, 0);

    /* Spacer to push Create button to bottom */
    GtkWidget *create_spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(create_card), create_spacer, TRUE, TRUE, 0);

    GtkWidget *create_btn = gtk_button_new_with_label("Create Volume");
    GtkWidget *create_icon = gtk_image_new_from_icon_name("document-new", GTK_ICON_SIZE_BUTTON);
    gtk_button_set_image(GTK_BUTTON(create_btn), create_icon);
    gtk_button_set_always_show_image(GTK_BUTTON(create_btn), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(create_btn), "btn-cyan");
    g_signal_connect(create_btn, "clicked", G_CALLBACK(on_create_volume_clicked), app_state);
    gtk_box_pack_end(GTK_BOX(create_card), create_btn, FALSE, FALSE, 0);


    /* Console status card */
    GtkWidget *console_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(console_card), "card");
    gtk_box_pack_start(GTK_BOX(content_vbox), console_card, FALSE, FALSE, 0);

    GtkWidget *lbl_console_title = gtk_label_new("SYSTEM STATUS CONSOLE");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_console_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_console_title), 0.0);
    gtk_box_pack_start(GTK_BOX(console_card), lbl_console_title, FALSE, FALSE, 0);

    app_state->status_label = gtk_label_new("System Ready");
    gtk_label_set_xalign(GTK_LABEL(app_state->status_label), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->status_label), "status");
    gtk_box_pack_start(GTK_BOX(console_card), app_state->status_label, FALSE, FALSE, 2);

    app_state->progress_bar = gtk_progress_bar_new();
    gtk_widget_set_size_request(app_state->progress_bar, -1, 6);
    gtk_box_pack_start(GTK_BOX(console_card), app_state->progress_bar, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(app_state->window), "app-state", app_state);

    /* Initialize telemetry data labels */
    update_telemetry(app_state);

    /* Create Splash Screen */
    GtkWidget *splash = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_decorated(GTK_WINDOW(splash), FALSE);
    gtk_window_set_position(GTK_WINDOW(splash), GTK_WIN_POS_CENTER);
    gtk_window_set_default_size(GTK_WINDOW(splash), 380, 420);
    
    GtkStyleContext *splash_context = gtk_widget_get_style_context(splash);
    gtk_style_context_add_class(splash_context, "splash-window");
    
    GtkWidget *splash_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(splash), splash_box);
    gtk_container_set_border_width(GTK_CONTAINER(splash_box), 20);
    
    /* Dynamically resolve axis_logo.png path */
    char *splash_path = NULL;
    char *cwd = g_get_current_dir();
    char *path1 = g_build_filename(cwd, "axis_logo.png", NULL);
    char *path2 = g_build_filename(cwd, "axis_logo.png", NULL);
    const char *splash_paths[] = {
        path1,
        path2,
        "axis_logo.png",
        "axis_logo.png",
        "/usr/share/axis/axis_logo.png",
        "/usr/local/share/axis/axis_logo.png",
        NULL
    };
    for (int i = 0; splash_paths[i] != NULL; i++) {
        if (g_file_test(splash_paths[i], G_FILE_TEST_EXISTS)) {
            splash_path = g_strdup(splash_paths[i]);
            break;
        }
    }
    g_free(cwd);
    g_free(path1);
    g_free(path2);
 
    GdkPixbuf *splash_pb = NULL;
    if (splash_path) {
        splash_pb = gdk_pixbuf_new_from_file_at_scale(splash_path, 300, 300, TRUE, NULL);
        g_free(splash_path);
    } else {
        splash_pb = gdk_pixbuf_new_from_file_at_scale("axis_logo.png", 300, 300, TRUE, NULL);
    }
    
    GtkWidget *splash_img;
    if (splash_pb) {
        splash_img = gtk_image_new_from_pixbuf(splash_pb);
        g_object_unref(splash_pb);
    } else {
        splash_img = gtk_image_new_from_icon_name("image-missing", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(splash_box), splash_img, TRUE, TRUE, 5);
    
    GtkWidget *loading_label = gtk_label_new("INITIALIZING");
    gtk_style_context_add_class(gtk_widget_get_style_context(loading_label), "splash-loading");
    gtk_box_pack_start(GTK_BOX(splash_box), loading_label, FALSE, FALSE, 5);

    GtkWidget *tagline_label = gtk_label_new("POST-QUANTUM ENCRYPTED STORAGE");
    gtk_style_context_add_class(gtk_widget_get_style_context(tagline_label), "splash-tagline");
    gtk_box_pack_start(GTK_BOX(splash_box), tagline_label, FALSE, FALSE, 0);
    
    GtkWidget *splash_progress = gtk_progress_bar_new();
    gtk_widget_set_size_request(splash_progress, 300, 6);
    gtk_box_pack_start(GTK_BOX(splash_box), splash_progress, FALSE, FALSE, 10);
    
    gtk_widget_show_all(splash);
    
    SplashTimeoutData *std = g_malloc(sizeof(SplashTimeoutData));
    std->splash = splash;
    std->main_window = app_state->window;
    std->progress = splash_progress;
    std->ticks = 0;
    
    g_timeout_add(100, on_splash_timeout, std);
}

/* Cleanup callback */
static void on_shutdown(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    GtkWindow *window = gtk_application_get_active_window(app);
    if (window) {
        AppState *app_state = g_object_get_data(G_OBJECT(window), "app-state");
        if (app_state) {
            if (app_state->current_volume) {
                if (app_state->current_volume->is_open) {
                    if (app_state->current_volume->vfs.is_mounted) {
                        stop_fuse_mount(app_state->current_volume);
                        volume_unmount(app_state->current_volume);
                    }
                    volume_close(app_state->current_volume, NULL, NULL);
                    free(app_state->current_volume);
                }
            }
            g_free(app_state);
        }
    }
}

/* Create GUI */
int create_gui(int argc, char **argv) {
    gtk_init(&argc, &argv);

    GtkApplication *app;
    int status;
    
    app = gtk_application_new("org.axis.disk", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    g_signal_connect(app, "shutdown", G_CALLBACK(on_shutdown), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    
    return status;
}
