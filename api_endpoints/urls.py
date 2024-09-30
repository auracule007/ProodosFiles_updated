from django.urls import path
from . import views

urlpatterns = [
    path('sign-up/', views.RegisterView.as_view(), name='sign_up_api'),
    path('verify/', views.VerifyEmailView.as_view(), name='verify_api'),
    path('login/', views.LoginView.as_view(), name='login'),

    path('upload_file/', views.FileUploadView.as_view(), name='api_upload_file'),
    path('download_file/', views.DownloadFileView.as_view(), name="download_f_api"),
    # path('download_file/', views.download_file, name="download_f_api"),
    path('download-signed/<str:signed_value>/', views.download_signed_file, name='serve_download_file'),
    path('share-file/', views.ShareFileAPIView.as_view(), name="share_file_api"), #undone

    path('resender/', views.ResendVerificationEmailView.as_view(), name="resend_verifi"),
    path("rest-pswd/", views.PasswordResetAPIView.as_view(), name="reset_paswrd"),
    path("forgot-pass/", views.PasswordResetRequestAPIView.as_view(), name="forgot_passw"),

    path("shared-f/", views.SharedFilesAPIView.as_view(), name="shared_files_api"), #duplicate(which one are you using)

    path("create-f/", views.FolderCreateAPIView.as_view(), name="create_fo"),
    path('get-folders/', views.UserFoldersAPIView.as_view(), name='user-folders'), #added
    path('all-folders/', views.AllFoldersAPIView.as_view(), name='all-folders'), #added
    path('user-files/', views.UserFilesAPIView.as_view(), name='user-files'), #added
    path("view_fo/", views.FolderViewAPIView.as_view(), name="view_fo"),

    path('fi/unzip/', views.UnzipFileAPIView.as_view(), name="unzip_file_api"), #undone
    path('fi/rename/', views.RenameFileAPIView.as_view(), name="rename_file_api"), #undone
    path('fi/copy/', views.CopySharedFileAPIView.as_view(), name='copy_shared_file_api'), #undone
    path("fi/move/", views.MoveFileAPIView.as_view(), name="move_file_api"), #undone

    # path("change-role", views.ChangeRoleAPIView.as_view(), name="change_role_api"),
    path("suggested/", views.SuggestedFilesAPIView.as_view(), name="suggested_file_api"), #undone
    path("starred-f/", views.GetStarredFilesAPIView.as_view(), name="starred_files_api"), #undone

    path("binned-f/", views.BinnedFilesAPIView.as_view(), name="binned_files_api"),

    path("fo/sharing/", views.ShareFolderAPIView.as_view(), name="fold_shar"), #undone
    path("fo/star/", views.StarFolderAPIView.as_view(), name="star_folder_api"),
    path("fo/bin/", views.BinFolderAPIView.as_view(), name="bin_fo_api"),
    path("fo/del/", views.DeletePermAPIView.as_view(), name="delete_perm_api"),

    path("fo/zip/", views.ZipFolderAPIView.as_view(), name="zip_folder_api"),  #undone
    path("fo/rename/", views.RenameFolderAPIView.as_view(), name="remove_folder_api"), #undone
    path("fo/move/", views.MoveFolderAPIView.as_view(), name="move_folder_api"), #undone

    path('serve-dc-img/<uuid:file_id>/<str:image_name>/', views.serve_secure_doc_image, name='serve_img'),
    # your other routes

]
