from fastapi import HTTPException
from github import Github, GithubException,InputGitTreeElement
from settings import GITHUB_TOKEN,GITHUB_REPO_URL


class GithubService:
    """
    Service to interact with GitHub.
    """

    def __init__(self):
        self.repo_url = GITHUB_REPO_URL
        self.token = GITHUB_TOKEN
        self.github = Github(self.token)
        self.repo = self.github.get_repo(self.repo_url)

    def backup_file(self, file_path: str, branch: str = "backup"):
        """
        Backup a file to a specified branch in the GitHub repository.

        Parameters:
            file_path (str): Path to the file to be backed up.
            branch (str): Branch name where the file will be backed up.

        Raises:
            HTTPException: If an error occurs during the backup process.
        """
        try:
            with open(file_path, 'r') as file:
                content = file.read()

            # Check if the branch exists, if not, create it
            try:
                ref = self.repo.get_git_ref(f'heads/{branch}')
            except GithubException as error:
                if error.status == 404:
                    # Get the default branch reference
                    main_ref = self.repo.get_git_ref('heads/master')
                    # Create the new branch from the default branch
                    ref = self.repo.create_git_ref(ref=f'refs/heads/{branch}', sha=main_ref.object.sha)
                    ref.edit(main_ref.object.sha, force=True)
                else:
                    raise

            # Get the latest commit
            latest_commit = self.repo.get_commit(ref.object.sha)
            # Create a new blob with the file content
            blob = self.repo.create_git_blob(content, "utf-8")
            # Create a new tree with the blob
            # Convert absolute path to relative path
            relative_path = file_path.split('/')[-1] 
            tree_element = InputGitTreeElement(
            path=relative_path,  # Use relative path
            mode='100644',
            type='blob',
            sha=blob.sha
            )
            tree = self.repo.create_git_tree([tree_element], latest_commit.commit.tree)
            # Create a new commit
            new_commit = self.repo.create_git_commit("Backup file", tree, [latest_commit.commit])
            # Update the reference to point to the new commit
            ref.edit(new_commit.sha)

            print(f"Successfully backed up {file_path} to branch {branch} in GitHub repository.")
        except GithubException as error:
            raise HTTPException(status_code=500, detail=f"An error occurred: {error}")

